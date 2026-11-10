#include "consensus/finality_state.h"
#include "consensus/finality_producer.h"
#include "consensus/governance.h"
#include <iostream>
#include <stdexcept>
using namespace veld;
namespace fq=veld::finality::qc;
static unsigned checks=0;
static void check(bool okay,const char* why){++checks;if(!okay)throw std::runtime_error(why);}
static std::string publicKey(const RealKeyPair& k){return BytesToHex(std::vector<uint8_t>(k.public_key.begin(),k.public_key.end()));}
int main(){try{
  static_assert(NMS_MIN_BOND_UNITS==1000ULL*VELD_UNITS);
  const bool active=ValidatorBondPolicyActive(4000);
  check(!ValidatorBondPolicyActive(3999),"historical policy preserved");
  check(MinimumValidatorBond(3999)==10000ULL*VELD_UNITS,"historical registration amount");
  check(MinimumValidatorBond(4000)==(active?5000ULL:10000ULL)*VELD_UNITS,"activation registration amount");
  check(ValidatorGovernanceBondFloor(4000)==(active?25000ULL:50000ULL)*VELD_UNITS,"governance aggregate threshold");
  ValidatorRegistry registry;auto original=registry.SnapshotState();std::vector<RealKeyPair> keys;
  for(unsigned i=0;i<7;++i){
    keys.push_back(GenerateKeyPair(false));ValidatorRecord r;r.pubkey_hex=publicKey(keys.back());r.address=keys.back().address;
    r.active=true;r.bond_custodial=true;r.bond_units=10000ULL*VELD_UNITS;r.registered_height=1;
    original.validators[r.pubkey_hex]=r;original.address_to_pubkey[r.address]=r.pubkey_hex;
  }
  registry.RestoreState(original);
  const auto historical=fq::BuildEpochSnapshot(registry,8,fq::SnapshotHeightFor(8));
  const auto historical_root=historical.root;
  check(fq::SnapshotQualifies(historical)&&historical.total_weight==70000ULL*VELD_UNITS,"historical seven-key snapshot valid");
  auto selected=original;
  selected.validators.at(publicKey(keys[5])).active=false;selected.validators.at(publicKey(keys[6])).active=false;
  registry.RestoreState(selected);
  const auto five=fq::BuildEpochSnapshot(registry,9,fq::SnapshotHeightFor(9));
  check(fq::SnapshotWellFormed(five)&&five.entries.size()==5,"five entries retain canonical snapshot");
  check(five.Qualified()==active,"five keys qualify only after activation");
  check(five.total_weight==(active?25000ULL:50000ULL)*VELD_UNITS,"snapshot weight uses its own height");
  check(fq::SnapshotWellFormed(historical)&&historical.root==historical_root,"old certificate membership remains valid");
  for(const auto& [pk,r]:registry.SnapshotState().validators)check(r.bond_units==10000ULL*VELD_UNITS,"lower threshold cannot release original principal");
  check(registry.GetGovernanceBondedTotal(3999)==50000ULL*VELD_UNITS,"historical governance weights");
  check(registry.GetGovernanceBondedTotal(4000)==(active?25000ULL:50000ULL)*VELD_UNITS,"new governance weights capped equally");
  for(uint64_t n=5;n<=10;++n)for(uint64_t signatures=0;signatures<=n;++signatures)
    check(fq::IsSupermajority(signatures*5000,n*5000)==(3*signatures>2*n),"strict greater-than-two-thirds quorum");
  check(!fq::IsSupermajority(15000,25000)&&fq::IsSupermajority(20000,25000),"five-member set requires four signatures");
  const auto genesis=Hash256d("disposable validator policy certificate");
  auto certificate=[&](const fq::EpochSnapshot& snapshot,unsigned count){
    fq::CertAssembler assembler;const uint64_t target=snapshot.epoch_id*fq::EPOCH_BLOCKS;
    for(unsigned i=0;i<count;++i){
      const auto& entry=snapshot.entries.at(i);
      const auto found=std::find_if(keys.begin(),keys.end(),[&](const auto& key){return publicKey(key)==entry.pubkey_hex;});
      check(found!=keys.end(),"disposable signing identity found");
      dilithium::PublicKey pub{};dilithium::SecretKey secret{};
      check(veld_mldsa65_keypair_from_seed(found->private_key.data(),pub.data(),secret.data())==0,"real signing seed expanded");
      fq::FinalityVoter voter(entry.pubkey_hex,secret);
      auto vote=voter.Prevote(snapshot,fq::CheckpointRound(target),{},{target,Hash256d("candidate checkpoint")},std::nullopt,false,fq::NETWORK_ID,genesis);
      check(vote&&assembler.Offer(*vote,snapshot,fq::NETWORK_ID,genesis),"genuine snapshotted signature admitted");
      compat::SecureZero(secret.data(),secret.size());
    }
    return assembler.TryAssemble(snapshot,fq::NETWORK_ID,genesis,fq::Phase::PREVOTE);
  };
  check(!certificate(historical,4),"historical set still refuses four-of-seven certificate");
  auto old_certificate=certificate(historical,5);
  check(old_certificate&&fq::VerifyDecodedQc(*old_certificate,historical,fq::NETWORK_ID,genesis),"historical five-of-seven certificate remains valid");
  if(active){
    check(!certificate(five,3),"three-of-five cannot form a real certificate");
    auto new_certificate=certificate(five,4);
    check(new_certificate&&fq::VerifyDecodedQc(*new_certificate,five,fq::NETWORK_ID,genesis),"four-of-five genuine certificate verifies");
    new_certificate->qc.target.hash[0]^=1;
    check(!fq::VerifyDecodedQc(*new_certificate,five,fq::NETWORK_ID,genesis),"certificate signatures bind the exact checkpoint");
  }
  auto mixed=five;mixed.entries.front().weight+=VELD_UNITS;
  check(!fq::SnapshotWellFormed(mixed),"mixed policy weights refused");
  auto relabeled=five;relabeled.snapshot_height=fq::SnapshotHeightFor(8);
  relabeled.root=fq::SnapshotRoot(relabeled.entries,relabeled.epoch_id,relabeled.snapshot_height,relabeled.total_weight);
  check(fq::SnapshotWellFormed(relabeled)==!active,"new weights cannot masquerade as historical snapshot");
  auto underbonded=original.validators.begin()->second;underbonded.bond_units=5000ULL*VELD_UNITS;
  check(!fq::QualifiedAt(underbonded,3999),"old epoch excludes five-thousand bond");
  check(fq::QualifiedAt(underbonded,4319)==active,"new mature bond eligible under selected policy");
  underbonded.registered_height=4000;
  check(!fq::QualifiedAt(underbonded,4319),"new registration still waits full maturity");
  check(fq::QualifiedAt(underbonded,4799)==active,"mature new bond admitted at later epoch");
  fq::FinalityState first,replayed;std::vector<fq::EpochSnapshot> history;
  for(uint64_t epoch=6;epoch<=10;++epoch){
    registry.RestoreState(epoch<=8?original:selected);
    auto s=fq::BuildEpochSnapshot(registry,epoch,fq::SnapshotHeightFor(epoch));
    check(first.OnEpochBoundary(s),"epoch transition accepted");history.push_back(s);
  }
  for(const auto&s:history)check(replayed.OnEpochBoundary(s),"historical epoch replay accepted");
  check(first.Digest()==replayed.Digest(),"old and new epoch replay produces identical finality state");
  check(first.FinalityActive()==active,"finality membership policy applied at snapshot boundary");
  for(uint64_t height:{3999ULL,4000ULL})for(uint64_t amount:{4999ULL,5000ULL,9999ULL,10000ULL}){
    const auto& key=keys.front();const auto operation=ValidatorRegistry::BuildRegisterOp(publicKey(key));
    std::vector<uint8_t> marker{0x6a,0x4d,uint8_t(operation.size()&255),uint8_t(operation.size()>>8)};
    marker.insert(marker.end(),operation.begin(),operation.end());Transaction tx;TxInput input;input.prev_tx_hash.fill(1);input.prev_out_index=0;tx.inputs.push_back(input);
    tx.outputs.emplace_back(amount*VELD_UNITS,AddressToScript(STAKE_VAULT_ADDRESS));tx.outputs.emplace_back(0,marker);
    tx.inputs[0].script_sig=key.SignInput(tx,0,AddressToScript(key.address)).script_sig;
    check(TxVerifiedSignedBy(tx,key.address),"disposable registration has real signature");
    Block block;block.height=height;block.transactions.push_back(tx);ValidatorRegistry admitted;admitted.SetTotalStaked(VALIDATOR_UNLOCK_STAKED);
    admitted.ProcessBlock(block,[](const auto&){return uint64_t{0};});
    const auto expected=amount*VELD_UNITS>=MinimumValidatorBond(height);
    check(admitted.IsRegistered(publicKey(key))==expected,"signed registration uses inclusion-height minimum");
    if(expected)check(admitted.SnapshotState().validators.at(publicKey(key)).bond_units==amount*VELD_UNITS,"full funded principal retained");
  }
  std::cout<<"PASS_VALIDATOR_POLICY checks="<<checks<<" candidate_active="<<active<<" funds=disposable production_activation=0\n";return 0;
}catch(const std::exception&e){std::cerr<<"FAIL "<<e.what()<<'\n';return 1;}}
