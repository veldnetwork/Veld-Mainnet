#pragma once

#include <algorithm>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <new>
#include <span>
#include <thread>
#include <vector>

#ifdef _WIN32
#include "../compat/platform.h"
#endif

namespace veld::mining {

inline constexpr unsigned MAX_MINING_WORKERS = 64;

inline constexpr bool ValidWorkerCount(uint64_t workers) {
    return workers >= 1 && workers <= MAX_MINING_WORKERS;
}

inline constexpr unsigned ClampWorkerCount(uint64_t workers) {
    return static_cast<unsigned>(std::clamp<uint64_t>(workers, 1, MAX_MINING_WORKERS));
}

struct CpuCapacity {
    unsigned logical{1};
    unsigned physical{1};
    bool topology_detected{false};
};

inline constexpr CpuCapacity EstimatedCpuCapacity(unsigned logical) {
    logical = std::max(1u, logical);
    return {logical, logical / 2 + logical % 2, false};
}

// Core masks are intersected with the CPUs available to this process. SMT
// siblings count as one core, including when only one sibling is available.
inline CpuCapacity CapacityFromCoreMasks(std::span<const uint64_t> cores, uint64_t process_mask) {
    auto fallback = EstimatedCpuCapacity(std::popcount(process_mask));
    if (process_mask == 0)
        return fallback;
    uint64_t represented = 0;
    unsigned physical = 0;
    for (const auto core : cores) {
        const auto visible = core & process_mask;
        if (visible == 0)
            continue;
        if (represented & visible)
            return fallback;
        represented |= visible;
        ++physical;
    }
    if (represented != process_mask || physical == 0)
        return fallback;
    return {static_cast<unsigned>(std::popcount(process_mask)), physical, true};
}

inline CpuCapacity DetectCpuCapacity() {
    auto fallback = EstimatedCpuCapacity(std::thread::hardware_concurrency());
#ifdef _WIN32
    DWORD_PTR process_mask = 0, system_mask = 0;
    if (!GetProcessAffinityMask(GetCurrentProcess(), &process_mask, &system_mask) ||
        process_mask == 0)
        return fallback;
    fallback = EstimatedCpuCapacity(std::popcount(static_cast<uint64_t>(process_mask)));
    // The miner currently supports at most 64 workers. Preserve the conservative
    // estimate on systems whose process affinity spans multiple processor groups.
    if (GetActiveProcessorGroupCount() != 1)
        return fallback;
    DWORD bytes = 0;
    if (GetLogicalProcessorInformationEx(RelationProcessorCore, nullptr, &bytes) ||
        GetLastError() != ERROR_INSUFFICIENT_BUFFER || bytes == 0 || bytes > 1024 * 1024)
        return fallback;
    try {
        std::vector<uint8_t> storage(bytes);
        if (!GetLogicalProcessorInformationEx(
                RelationProcessorCore,
                reinterpret_cast<PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX>(storage.data()),
                &bytes) ||
            bytes > storage.size())
            return fallback;
        std::vector<uint64_t> cores;
        size_t offset = 0;
        constexpr size_t processor_offset =
            offsetof(SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX, Processor);
        while (offset < bytes) {
            if (bytes - offset < processor_offset)
                return fallback;
            DWORD length = 0;
            LOGICAL_PROCESSOR_RELATIONSHIP relationship{};
            std::memcpy(&length,
                        storage.data() + offset +
                            offsetof(SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX, Size),
                        sizeof(length));
            std::memcpy(&relationship, storage.data() + offset, sizeof(relationship));
            if (length < processor_offset + sizeof(PROCESSOR_RELATIONSHIP) ||
                length > bytes - offset || relationship != RelationProcessorCore)
                return fallback;
            PROCESSOR_RELATIONSHIP processor{};
            std::memcpy(&processor, storage.data() + offset + processor_offset, sizeof(processor));
            if (processor.GroupCount != 1 || processor.GroupMask[0].Group != 0)
                return fallback;
            cores.push_back(static_cast<uint64_t>(processor.GroupMask[0].Mask));
            offset += length;
        }
        return CapacityFromCoreMasks(cores, process_mask);
    } catch (const std::bad_alloc&) {
        return fallback;
    }
#else
    return fallback;
#endif
}

inline constexpr unsigned DefaultWorkerCount(const CpuCapacity& capacity) {
    const auto physical = std::clamp(capacity.physical, 1u, std::max(1u, capacity.logical));
    return ClampWorkerCount(physical > 1 ? physical - 1 : 1);
}

inline constexpr unsigned PresetWorkerCount(const CpuCapacity& capacity, int preset) {
    const auto physical = std::clamp(capacity.physical, 1u, std::max(1u, capacity.logical));
    if (preset == 0)
        return ClampWorkerCount((uint64_t(physical) + 3) / 4);
    if (preset == 2)
        return ClampWorkerCount(physical);
    return ClampWorkerCount((uint64_t(physical) * 3 + 3) / 4);
}

} // namespace veld::mining
