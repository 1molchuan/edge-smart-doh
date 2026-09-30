export async function matchCache(cache: Cache, key: Request): Promise<Response | undefined> {
  try {
    return await cache.match(key);
  } catch {
    // EdgeOne throws for an expired/missing cache entry in some runtime versions.
    // Cache failures must degrade to a miss for DNS resolution to remain available.
    return undefined;
  }
}
