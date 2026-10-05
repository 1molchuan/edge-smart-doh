import type { AppConfig } from "./config";
import { domainMatches } from "./dns/ecs";
import { DnsType, type DnsPacket } from "./dns/types";
import type { PlanContext, RoutePlan } from "./plan";
import { flattenAliases, injectEch, injectEchBytes, pinAddresses, pinHttpsHints, responseUsesCloudflare, rewriteCloudflareAddresses, rewriteXAddresses } from "./rewrite";

/**
 * Applies a RoutePlan to an answer. No decisions are taken here: everything comes from the plan, in
 * one fixed order (address rewrites, configured ECH, planned ECH, hints, post edits, CNAME flattening).
 * `upstream` is the answer as upstream gave it, `answer` the same after response rules.
 */
export function renderPlan(plan: RoutePlan, ctx: PlanContext, config: AppConfig, upstream: DnsPacket, answer: DnsPacket): DnsPacket {
  const { query, notes } = ctx;
  if (plan.passthrough) return plan.passthrough(answer);
  const question = query.questions[0]!;
  let packet = answer;

  if (plan.preferredPool && ctx.ranges) {
    const before = packet;
    packet = rewriteCloudflareAddresses(packet, ctx.ranges, config);
    if (packet !== before) {
      notes?.push(`Cloudflare addresses rewritten to the preferred pool (${[...config.cfPreferredIpv4, ...config.cfPreferredIpv6].join(", ")})`);
      if (plan.strategy === "direct") plan.strategy = "preferred-ip";
    }
  }
  if (plan.xPool) packet = rewriteXAddresses(packet, query, config);
  if (plan.pin) packet = pinAddresses(packet, query, plan.pin, plan.pinTtl);

  const beforeConfiguredEch = packet;
  packet = injectEch(packet, config);
  if (packet !== beforeConfiguredEch) notes?.push("ECH injected from ECH_CONFIG_BASE64 (ECH_DOMAINS)");
  if (plan.ech) packet = injectEchBytes(packet, plan.ech.config, plan.ech.alpn);
  if (plan.hints) packet = pinHttpsHints(packet, plan.hints);

  for (const edit of plan.post) {
    const before = packet;
    packet = edit.apply(packet);
    if (packet !== before) notes?.push(edit.note);
  }

  if (question.type === DnsType.A || question.type === DnsType.AAAA || question.type === DnsType.HTTPS) {
    // Every answer type of an ECH host must sit at one canonical name, or Chromium drops the ECH
    // config (see flattenAliases). ECH hosts: Cloudflare-served (by address or X classification),
    // Meta, and explicitly configured ECH domains. Judged on the upstream addresses: the preferred
    // pool the answer was rewritten to need not fall inside the published Cloudflare ranges.
    const addresses = {
      ipv4: upstream.answers.flatMap((record) => (record.rdata.kind === "a" ? [record.rdata.address] : [])),
      ipv6: upstream.answers.flatMap((record) => (record.rdata.kind === "aaaa" ? [record.rdata.address] : [])),
    };
    const echHost = config.echEnabled && (domainMatches(question.name, config.metaDomains) || domainMatches(question.name, config.echDomains));
    if (echHost || ctx.classified() === true || (ctx.ranges !== undefined && responseUsesCloudflare(addresses, ctx.ranges))) {
      const before = packet;
      packet = flattenAliases(packet);
      if (packet !== before) notes?.push(`CNAME chain flattened: every record now sits at ${question.name} (Chromium needs this to use ECH)`);
    }
  }
  return packet;
}
