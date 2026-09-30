import { handleRequest, type RequestRuntime } from "./index";

interface EdgeOneRequestProperties {
  clientIp?: string;
  geo?: {
    asn?: number;
    countryCodeAlpha2?: string;
    countryName?: string;
    regionName?: string;
    cityName?: string;
  };
  uuid?: string;
}

type EdgeOneRequest = Request & { eo?: EdgeOneRequestProperties; version?: string };

declare const env: Env;

const edgeOneRuntime: RequestRuntime = {
  clientIp(request) {
    return (request as EdgeOneRequest).eo?.clientIp;
  },
  probe(request) {
    const edgeRequest = request as EdgeOneRequest;
    const eo = edgeRequest.eo;
    return {
      provider: "edgeone",
      country: eo?.geo?.countryCodeAlpha2,
      countryName: eo?.geo?.countryName,
      region: eo?.geo?.regionName,
      city: eo?.geo?.cityName,
      asn: eo?.geo?.asn,
      httpProtocol: edgeRequest.version,
      requestId: eo?.uuid,
    };
  },
};

addEventListener("fetch", (rawEvent) => {
  const event = rawEvent as FetchEvent;
  event.respondWith(handleRequest(event.request, env, event, edgeOneRuntime));
});
