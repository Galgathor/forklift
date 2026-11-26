import { useEffect, useState } from "react";
import { FieldHelp, Help } from "./Help";

export type HostDnsConfig = {
  zone: string;
  fqdn: string;
  ipv4: string;
  ipv6: string | null;
  reverse: boolean;
};
type Api = (path: string) => Promise<unknown>;
export type HostDnsZones = {
  available: boolean;
  error?: string;
  default_host_zone?: string | null;
  zones: { name: string; managed: boolean }[];
};

export function forwardZones(zones: HostDnsZones["zones"]) {
  return zones
    .filter((zone) => zone.managed && !zone.name.endsWith(".arpa."))
    .map((zone) => zone.name)
    .sort();
}

export function isIpv4(value: string) {
  return (
    /^(0|[1-9]\d{0,2})(\.(0|[1-9]\d{0,2})){3}$/.test(value) &&
    value.split(".").every((octet) => Number(octet) <= 255)
  );
}

export function reportedIpv4(addresses: { address: string }[]) {
  const values = [
    ...new Set(addresses.map((entry) => entry.address).filter(isIpv4)),
  ];
  return values.length === 1 ? values[0] : "";
}

export function hostDnsFromForm(form: FormData): HostDnsConfig | null {
  if (!form.has("dns_managed")) return null;
  return {
    zone: String(form.get("dns_zone")),
    fqdn: String(form.get("dns_fqdn")),
    ipv4: String(form.get("dns_ipv4")).trim(),
    ipv6: String(form.get("dns_ipv6") || "") || null,
    reverse: form.has("dns_reverse"),
  };
}

export function HostDnsFields({
  api,
  hostname,
  initial,
  suggestedIp = "",
  hasExistingRecords = false,
}: {
  api: Api;
  hostname: string;
  initial?: HostDnsConfig | null;
  suggestedIp?: string;
  hasExistingRecords?: boolean;
}) {
  const [ipv4, setIpv4] = useState(initial?.ipv4 || suggestedIp);
  const [enabled, setEnabled] = useState<boolean | null>(
    initial ? true : hasExistingRecords ? false : null,
  );
  const [choices, setChoices] = useState<string[]>([]);
  const [preferredZone, setPreferredZone] = useState("");
  const [selectedZone, setSelectedZone] = useState(initial?.zone || "");
  const [fqdn, setFqdn] = useState<string | null>(initial?.fqdn ?? null);
  const [error, setError] = useState("");
  const [loaded, setLoaded] = useState(false);
  const host = hostname.trim().toLowerCase().replace(/\.$/, "");
  const automatic = !!host && host !== ipv4.trim() && isIpv4(ipv4.trim());
  const zone = selectedZone || preferredZone;
  const managed = enabled ?? (automatic && !!zone);
  const suffix = zone.replace(/\.$/, "");
  const suggestedName =
    suffix && (host === suffix || host.endsWith(`.${suffix}`))
      ? host
      : host.split(".")[0];

  useEffect(() => {
    let active = true;
    void api("dns")
      .then((result) => {
        if (!active) return;
        const value = result as HostDnsZones;
        const zones = forwardZones(value.zones);
        setChoices(zones);
        setPreferredZone(
          zones.find((name) => name === value.default_host_zone) ||
            zones[0] ||
            "",
        );
        if (!value.available)
          setError(value.error || "DNS zones are unavailable.");
      })
      .catch((e: Error) => {
        if (active) setError(e.message);
      })
      .finally(() => {
        if (active) setLoaded(true);
      });
    return () => {
      active = false;
    };
  }, []);

  return (
    <fieldset>
      <legend>DNS registration</legend>
      <label className="checkbox">
        <input
          name="dns_managed"
          type="checkbox"
          checked={managed}
          onChange={(e) => setEnabled(e.target.checked)}
        />
        Manage this host’s DNS records
      </label>
      <label>
        IPv4 address
        <input
          name="dns_ipv4"
          value={ipv4}
          onChange={(e) => setIpv4(e.target.value)}
          placeholder="192.168.1.50"
          required={managed}
        />
      </label>
      {error && (
        <p className="hint" role="status">
          {error}
        </p>
      )}
      {managed && (
        <>
          <FieldHelp
            label="Choosing a DNS zone"
            caption="DNS zone"
            help="Choose a managed forward zone for this hostname."
          >
            <select
              name="dns_zone"
              value={zone}
              onChange={(e) => setSelectedZone(e.target.value)}
              required
            >
              <option value="">
                {loaded
                  ? "Select a managed forward zone"
                  : "Loading DNS zones…"}
              </option>
              {[
                ...new Set([
                  ...choices,
                  ...(initial?.zone ? [initial.zone] : []),
                ]),
              ].map((name) => (
                <option key={name} value={name}>
                  {name}
                </option>
              ))}
            </select>
          </FieldHelp>
          <label>
            DNS name
            <input
              name="dns_fqdn"
              value={fqdn ?? suggestedName}
              onChange={(e) => setFqdn(e.target.value)}
              required
            />
          </label>
          <label>
            IPv6 address (optional)
            <input
              name="dns_ipv6"
              defaultValue={initial?.ipv6 || ""}
              placeholder="fd00::50"
            />
          </label>
          <div className="help-row checkbox-help">
            <label className="checkbox">
              <input
                name="dns_reverse"
                type="checkbox"
                defaultChecked={initial?.reverse ?? true}
              />
              Create matching reverse DNS
            </label>
            <Help label="Host DNS registration">
              A matching reverse zone is required. Forklift applies the DNS
              records when you save the host.
            </Help>
          </div>
        </>
      )}
      {!managed && hasExistingRecords && (
        <label>
          Existing managed DNS records
          <select name="dns_cleanup" defaultValue="keep">
            <option value="keep">Keep records and release ownership</option>
            <option value="delete">
              Delete only this host’s managed values
            </option>
          </select>
        </label>
      )}
    </fieldset>
  );
}
