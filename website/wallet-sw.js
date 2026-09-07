// Current documents and assets always come from the network.
// No offline HTML or expired response is substituted after a failed request.
const CACHE_PREFIX = 'veld-wallet-';
self.addEventListener('install', event => {
  event.waitUntil(self.skipWaiting());
});
self.addEventListener('activate', event => {
  event.waitUntil(caches.keys().then(keys => Promise.all(
    keys.filter(key => key.startsWith(CACHE_PREFIX))
        .map(key => caches.delete(key))
  )).then(() => self.clients.claim()));
});
self.addEventListener('fetch', event => {
  if (event.request.method === 'GET') {
    event.respondWith(fetch(event.request, {cache: 'no-store'}));
  }
});
