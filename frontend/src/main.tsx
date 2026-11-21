import React, { useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import {
  Boxes,
  LayoutDashboard,
  Users,
  UsersRound,
  Server,
  Database,
  Settings,
  Sun,
  Moon,
  LogOut,
  Plus,
  Search,
  CheckCircle2,
  Activity,
  ShieldCheck,
  X,
  Trash2,
  Pencil,
} from "lucide-react";
import "./style.css";
type Entry = { dn: string; attrs: Record<string, string[]> };
type Overview = {
  directory: { name: string; base: string };
  users: Entry[];
  groups: Entry[];
  events: { at: number; actor: string; action: string; target: string }[];
  ldap: string;
};
const attr = (e: Entry, k: string) => e.attrs[k]?.[0] || "";
function App() {
  const [configured, setConfigured] = useState<boolean | null>(null),
    [session, setSession] = useState<{ username: string; csrf: string } | null>(
      null,
    ),
    [data, setData] = useState<Overview | null>(null),
    [page, setPage] = useState("Dashboard"),
    [error, setError] = useState(""),
    [busy, setBusy] = useState(false),
    [query, setQuery] = useState(""),
    [modal, setModal] = useState<{ kind: string; entry?: Entry } | null>(null),
    [light, setLight] = useState(localStorage.getItem("theme") === "light");
  async function api(path: string, method = "GET", body?: unknown) {
    const r = await fetch("/api/" + path, {
      method,
      headers: {
        "Content-Type": "application/json",
        ...(session ? { "X-CSRF-Token": session.csrf } : {}),
      },
      body: body ? JSON.stringify(body) : undefined,
    });
    const v = await r.json();
    if (!r.ok) throw Error(v.error || "Request failed");
    return v;
  }
  async function refresh() {
    setData(await api("overview"));
  }
  async function perform(f: () => Promise<void>) {
    setBusy(true);
    setError("");
    try {
      await f();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  useEffect(() => {
    perform(async () => {
      const s = await api("status");
      setConfigured(s.configured);
      if (s.configured) {
        try {
          setSession(await api("me"));
        } catch {
          setSession(null);
        }
      }
    });
  }, []);
  useEffect(() => {
    if (session) perform(refresh);
  }, [session]);
  useEffect(() => {
    document.documentElement.dataset.theme = light ? "light" : "dark";
    localStorage.setItem("theme", light ? "light" : "dark");
  }, [light]);
  function submit(
    e: React.FormEvent<HTMLFormElement>,
    fn: (v: Record<string, string>) => Promise<void>,
  ) {
    e.preventDefault();
    const values = Object.fromEntries(new FormData(e.currentTarget)) as Record<
      string,
      string
    >;
    perform(() => fn(values));
  }
  const field = (
    name: string,
    label: string,
    value = "",
    type = "text",
    required = true,
  ) => (
    <label key={name}>
      {label}
      <input
        name={name}
        defaultValue={value}
        type={type}
        required={required}
        readOnly={name === "username" && !!modal?.entry}
        autoComplete={type === "password" ? "new-password" : undefined}
      />
    </label>
  );
  const banner = error && (
    <div className="error" role="alert">
      {error}
      <button onClick={() => setError("")} aria-label="Dismiss error">
        <X size={16} />
      </button>
    </div>
  );
  if (configured === null)
    return (
      <div className="auth">
        <Boxes size={40} />
        <p>Connecting to Forklift…</p>
        {banner}
      </div>
    );
  if (!configured || !session)
    return (
      <div className="auth">
        <div className="auth-card">
          <div className="brand">
            <span className="mark">
              <Boxes />
            </span>{" "}
            forklift<span className="tag">EARLY ACCESS</span>
          </div>
          <p className="eyebrow">YOUR DIRECTORY, SIMPLIFIED</p>
          <h1>
            {configured ? "Welcome back." : "A home for your identities."}
          </h1>
          <p className="muted">
            {configured
              ? "Sign in with your directory administrator account."
              : "Initialize your encrypted OpenLDAP directory. Your existing data is never reset."}
          </p>
          {banner}
          <form
            onSubmit={(e) =>
              submit(e, async (v) => {
                if (!configured) {
                  await api("setup", "POST", v);
                  setConfigured(true);
                } else setSession(await api("login", "POST", v));
              })
            }
          >
            {!configured && (
              <>
                {field("token", "One-time bootstrap token", "", "password")}
                {field("name", "Directory name", "Homelab")}
                {field("base", "LDAP base DN", "dc=homelab,dc=internal")}
                <p className="hint">
                  Use at least two dc= components. TLS and persistent storage
                  are prepared by the installer.
                </p>
              </>
            )}
            {field(
              "username",
              configured ? "Username" : "Initial administrator",
              "",
              "text",
            )}
            {field("password", "Password (14+ characters)", "", "password")}
            <button className="primary" disabled={busy}>
              {busy
                ? "Connecting…"
                : configured
                  ? "Sign in"
                  : "Initialize directory"}
            </button>
          </form>
          <div className="secure">
            <ShieldCheck size={16} /> Encrypted directory connections · Local
            persistent storage
          </div>
        </div>
      </div>
    );
  const nav = [
    ["Dashboard", LayoutDashboard],
    ["Users", Users],
    ["Groups", UsersRound],
    ["Hosts", Server],
    ["Directory Servers", Database],
    ["Settings", Settings],
  ] as const;
  return (
    <div className="layout">
      <aside>
        <div className="brand">
          <span className="mark">
            <Boxes />
          </span>{" "}
          forklift
        </div>
        <div className="workspace">
          <span className="workspace-icon">
            {data?.directory.name.slice(0, 1) || "F"}
          </span>
          <div>
            {data?.directory.name || "Directory"}
            <small>Local workspace</small>
          </div>
        </div>
        <div className="nav-label">WORKSPACE</div>
        <nav>
          {nav.map(([label, Icon]) => (
            <button
              className={page === label ? "active" : ""}
              key={label}
              onClick={() => {
                setPage(label);
                setQuery("");
              }}
            >
              <Icon size={19} />
              {label}
              {label === "Users" && data && (
                <span className="count">{data.users.length}</span>
              )}
            </button>
          ))}
        </nav>
        <div className="sidebar-bottom">
          <div className="secure">
            <ShieldCheck size={17} /> OpenLDAP, made simple
          </div>
          <small>Forklift v0.1 · Milestone 1</small>
        </div>
      </aside>
      <div className="main">
        <header>
          <span>
            Workspace <span className="muted">/</span> {page}
          </span>
          <div>
            <button aria-label="Toggle theme" onClick={() => setLight(!light)}>
              {light ? <Moon size={18} /> : <Sun size={18} />}
            </button>
            <span className="avatar">
              {session.username.slice(0, 2).toUpperCase()}
            </span>
            <span>{session.username}</span>
            <button
              aria-label="Sign out"
              onClick={() =>
                perform(async () => {
                  await api("logout", "POST", {});
                  setSession(null);
                  setData(null);
                })
              }
            >
              <LogOut size={18} />
            </button>
          </div>
        </header>
        <main>
          {banner}
          <div className="page-heading">
            <div>
              <p className="eyebrow">DIRECTORY MANAGEMENT</p>
              <h1>
                {page === "Dashboard" ? "Your directory at a glance." : page}
              </h1>
              <p className="muted">
                {page === "Dashboard"
                  ? "A clear view of the identities that power your homelab."
                  : page === "Users"
                    ? "Manage people, credentials, and Unix identities."
                    : page === "Groups"
                      ? "Organize accounts into practical access groups."
                      : "Configuration and operational information."}
              </p>
            </div>
            {["Users", "Groups"].includes(page) ? (
              <button
                className="primary"
                onClick={() => setModal({ kind: page })}
              >
                <Plus size={18} />
                Create {page === "Users" ? "user" : "group"}
              </button>
            ) : (
              <button
                className="secondary"
                disabled={busy}
                onClick={() => perform(refresh)}
              >
                <Activity size={17} />
                Refresh status
              </button>
            )}
          </div>
          {!data ? (
            <p className="muted">
              {error
                ? "Directory data is unavailable. Resolve the error, then refresh."
                : "Loading directory…"}
            </p>
          ) : (
            <>
              {page === "Dashboard" && (
                <>
                  <div className="stats">
                    {[
                      [
                        Users,
                        "Directory users",
                        data.users.length,
                        "Centrally managed accounts",
                      ],
                      [
                        UsersRound,
                        "Groups",
                        data.groups.length,
                        "POSIX-compatible groups",
                      ],
                      [
                        Database,
                        "Directory servers",
                        1,
                        "Primary directory connected",
                      ],
                    ].map(([Icon, label, value, caption]) => {
                      const I = Icon as typeof Users;
                      return (
                        <section className="stat" key={String(label)}>
                          <div>
                            <span>{String(label)}</span>
                            <I size={20} />
                          </div>
                          <strong>{String(value)}</strong>
                          <small>{String(caption)}</small>
                        </section>
                      );
                    })}
                  </div>
                  <div className="dashboard-grid">
                    <section className="panel directory">
                      <div className="panel-title">
                        <h2>Directory health</h2>
                        <span className="pill">
                          <CheckCircle2 size={14} />
                          Connected
                        </span>
                      </div>
                      <div className="directory-art">
                        <div className="db-icon">
                          <Database size={36} />
                        </div>
                        <h2>{data.directory.name}</h2>
                        <p className="muted">{data.directory.base}</p>
                      </div>
                      <dl>
                        <div>
                          <dt>Directory endpoint</dt>
                          <dd>ldaps://ldap:636</dd>
                        </div>
                        <div>
                          <dt>Role</dt>
                          <dd>Read / write primary</dd>
                        </div>
                        <div>
                          <dt>Transport</dt>
                          <dd>Certificate-verified TLS</dd>
                        </div>
                      </dl>
                      <p className="hint">
                        Connectivity checked on refresh. Replication is planned
                        for Milestone 3.
                      </p>
                    </section>
                    <section className="panel">
                      <div className="panel-title">
                        <h2>Recent activity</h2>
                        <Activity size={18} />
                      </div>
                      <div className="events">
                        {data.events.length ? (
                          data.events.slice(0, 7).map((e, i) => (
                            <div className="event" key={i}>
                              <span className="event-icon">
                                <ShieldCheck size={16} />
                              </span>
                              <div>
                                <strong>
                                  {e.action}{" "}
                                  <span className="muted">· {e.target}</span>
                                </strong>
                                <small>
                                  {e.actor} ·{" "}
                                  {new Date(e.at * 1000).toLocaleString()}
                                </small>
                              </div>
                            </div>
                          ))
                        ) : (
                          <p className="muted">
                            Administrative changes will appear here.
                          </p>
                        )}
                      </div>
                    </section>
                  </div>
                  <section className="callout">
                    <ShieldCheck size={24} />
                    <div>
                      <h3>Built on the directory you can trust.</h3>
                      <p>
                        OpenLDAP keeps serving identities independently of the
                        Forklift management app.
                      </p>
                    </div>
                  </section>
                </>
              )}
              {["Users", "Groups"].includes(page) && (
                <section className="panel">
                  <div className="table-toolbar">
                    <h2>
                      {page}{" "}
                      <span className="muted">
                        {(page === "Users" ? data.users : data.groups).length}
                      </span>
                    </h2>
                    <div className="search">
                      <Search size={17} />
                      <input
                        placeholder={`Search ${page.toLowerCase()}…`}
                        value={query}
                        onChange={(e) => setQuery(e.target.value)}
                      />
                    </div>
                  </div>
                  <div className="table-scroll">
                    <table>
                      <thead>
                        <tr>
                          <th>{page === "Users" ? "Account" : "Group"}</th>
                          <th>{page === "Users" ? "Unix identity" : "GID"}</th>
                          <th>{page === "Users" ? "Status" : "Members"}</th>
                          <th>Actions</th>
                        </tr>
                      </thead>
                      <tbody>
                        {(page === "Users" ? data.users : data.groups)
                          .filter((e) =>
                            JSON.stringify(e.attrs)
                              .toLowerCase()
                              .includes(query.toLowerCase()),
                          )
                          .map((e) => (
                            <tr key={e.dn}>
                              <td>
                                <div className="identity">
                                  <span className="avatar">
                                    {attr(e, page === "Users" ? "uid" : "cn")
                                      .slice(0, 2)
                                      .toUpperCase()}
                                  </span>
                                  <div>
                                    <strong>{attr(e, "cn")}</strong>
                                    <small>
                                      {attr(
                                        e,
                                        page === "Users"
                                          ? "uid"
                                          : "description",
                                      ) || "POSIX group"}
                                    </small>
                                  </div>
                                </div>
                              </td>
                              <td>
                                {attr(
                                  e,
                                  page === "Users" ? "uidNumber" : "gidNumber",
                                )}
                                {page === "Users" && (
                                  <small>{attr(e, "homeDirectory")}</small>
                                )}
                              </td>
                              <td>
                                {page === "Users" ? (
                                  <span
                                    className={
                                      attr(e, "shadowExpire") === "1"
                                        ? "badge"
                                        : "pill"
                                    }
                                  >
                                    {attr(e, "shadowExpire") === "1"
                                      ? "Disabled"
                                      : "Active"}
                                  </span>
                                ) : (
                                  (e.attrs.memberUid || []).join(", ") ||
                                  "No members"
                                )}
                              </td>
                              <td>
                                <div className="actions">
                                  <button
                                    aria-label="Edit"
                                    onClick={() =>
                                      setModal({ kind: page, entry: e })
                                    }
                                  >
                                    <Pencil size={16} />
                                  </button>
                                  <button
                                    aria-label="Delete"
                                    onClick={() => {
                                      if (
                                        confirm(
                                          `Delete ${attr(e, page === "Users" ? "uid" : "cn")}? This cannot be undone.`,
                                        )
                                      )
                                        perform(async () => {
                                          await api(
                                            `${page.toLowerCase()}/${attr(e, page === "Users" ? "uid" : "cn")}`,
                                            "DELETE",
                                          );
                                          await refresh();
                                        });
                                    }}
                                  >
                                    <Trash2 size={16} />
                                  </button>
                                </div>
                              </td>
                            </tr>
                          ))}
                      </tbody>
                    </table>
                  </div>
                </section>
              )}
              {page === "Directory Servers" && (
                <section className="panel">
                  <div className="panel-title">
                    <h2>Primary directory</h2>
                    <span className="pill">LDAP connected</span>
                  </div>
                  <dl>
                    <div>
                      <dt>Endpoint</dt>
                      <dd>ldaps://ldap:636</dd>
                    </div>
                    <div>
                      <dt>Base DN</dt>
                      <dd>{data.directory.base}</dd>
                    </div>
                    <div>
                      <dt>Replication</dt>
                      <dd>Not implemented · Milestone 3</dd>
                    </div>
                  </dl>
                  <p className="hint">
                    Replica enrollment, synchronization monitoring, and failover
                    testing are planned. This release manages one primary.
                  </p>
                </section>
              )}
              {page === "Hosts" && (
                <section className="empty panel">
                  <Server size={38} />
                  <h2>Linux integration is next.</h2>
                  <p className="muted">
                    Host enrollment, SSSD configuration downloads and Ansible
                    deployment are planned for Milestone 2.
                  </p>
                  <p>No hosts are enrolled by this release.</p>
                </section>
              )}
              {page === "Settings" && (
                <>
                  <section className="panel">
                    <h2>Installation</h2>
                    <dl>
                      <div>
                        <dt>Directory name</dt>
                        <dd>{data.directory.name}</dd>
                      </div>
                      <div>
                        <dt>Base DN</dt>
                        <dd>{data.directory.base}</dd>
                      </div>
                      <div>
                        <dt>Administrator group</dt>
                        <dd>administrators</dd>
                      </div>
                      <div>
                        <dt>Backups and certificate rotation</dt>
                        <dd>Offline operations · see README</dd>
                      </div>
                    </dl>
                  </section>
                  <section className="panel">
                    <h2>Administrative audit log</h2>
                    <div className="events">
                      {data.events.map((e, i) => (
                        <div className="event" key={i}>
                          <ShieldCheck size={17} />
                          <div>
                            <strong>
                              {e.actor}: {e.action} · {e.target}
                            </strong>
                            <small>
                              {new Date(e.at * 1000).toLocaleString()}
                            </small>
                          </div>
                        </div>
                      ))}
                    </div>
                  </section>
                </>
              )}
            </>
          )}
        </main>
        <footer>
          Forklift{" "}
          <span>Self-hosted identities. Straightforward administration.</span>
        </footer>
      </div>
      {modal && (
        <div className="overlay">
          <section
            className="dialog"
            role="dialog"
            aria-modal="true"
            aria-label={`Edit ${modal.kind}`}
          >
            <div className="panel-title">
              <h2>
                {modal.entry ? "Edit" : "Create"}{" "}
                {modal.kind === "Users" ? "user" : "group"}
              </h2>
              <button aria-label="Close" onClick={() => setModal(null)}>
                <X />
              </button>
            </div>
            {banner}
            <form
              onSubmit={(e) =>
                submit(e, async (v) => {
                  if (modal.kind === "Users") {
                    await api("users", "POST", {
                      ...v,
                      home:
                        v.home === "/home/username"
                          ? "/home/" + v.username
                          : v.home,
                      gid: Number(v.gid),
                      disabled: v.disabled === "on",
                      password: v.password || undefined,
                    });
                  } else {
                    await api(
                      "groups/" +
                        (modal.entry ? attr(modal.entry, "cn") : v.name),
                      "PUT",
                      {
                        name: v.name,
                        members: v.members
                          .split(",")
                          .map((s) => s.trim())
                          .filter(Boolean),
                      },
                    );
                  }
                  setModal(null);
                  await refresh();
                })
              }
            >
              {modal.kind === "Users" ? (
                <>
                  {field(
                    "username",
                    "Username",
                    modal.entry ? attr(modal.entry, "uid") : "",
                  )}
                  {modal.entry && (
                    <p className="hint">
                      Keep the username unchanged. Renaming Unix accounts is not
                      supported.
                    </p>
                  )}
                  {field(
                    "display_name",
                    "Display name",
                    modal.entry ? attr(modal.entry, "cn") : "",
                  )}
                  {field(
                    "email",
                    "Email",
                    modal.entry ? attr(modal.entry, "mail") : "",
                    "email",
                    false,
                  )}
                  {field(
                    "description",
                    "Description",
                    modal.entry ? attr(modal.entry, "description") : "",
                    "text",
                    false,
                  )}
                  <div className="form-grid">
                    {field(
                      "home",
                      "Home directory",
                      modal.entry
                        ? attr(modal.entry, "homeDirectory")
                        : "/home/username",
                    )}
                    <label>
                      Login shell
                      <select
                        name="shell"
                        defaultValue={
                          modal.entry
                            ? attr(modal.entry, "loginShell")
                            : "/bin/bash"
                        }
                      >
                        {["/bin/bash", "/bin/sh", "/usr/sbin/nologin"].map(
                          (s) => (
                            <option key={s}>{s}</option>
                          ),
                        )}
                      </select>
                    </label>
                  </div>
                  <label>
                    Primary group
                    <select
                      name="gid"
                      defaultValue={
                        modal.entry ? attr(modal.entry, "gidNumber") : undefined
                      }
                    >
                      {data?.groups.map((g) => (
                        <option key={g.dn} value={attr(g, "gidNumber")}>
                          {attr(g, "cn")} · {attr(g, "gidNumber")}
                        </option>
                      ))}
                    </select>
                  </label>
                  {field(
                    "password",
                    modal.entry
                      ? "New password (leave blank to keep)"
                      : "Initial password",
                    "",
                    "password",
                    !modal.entry,
                  )}
                  <p className="hint">
                    Disabling removes the password and expires the account. Set
                    a new password when enabling it again. Unix IDs are
                    allocated automatically and never reused.
                  </p>
                  <label className="checkbox">
                    <input
                      name="disabled"
                      type="checkbox"
                      defaultChecked={
                        !!modal.entry &&
                        attr(modal.entry, "shadowExpire") === "1"
                      }
                    />
                    Disable account
                  </label>
                  {modal.entry && (
                    <p className="hint">
                      Created {attr(modal.entry, "createTimestamp")} · Modified{" "}
                      {attr(modal.entry, "modifyTimestamp")}
                    </p>
                  )}
                </>
              ) : (
                <>
                  {field(
                    "name",
                    "Group name",
                    modal.entry ? attr(modal.entry, "cn") : "",
                  )}
                  {field(
                    "members",
                    "Member usernames (comma separated)",
                    modal.entry
                      ? (modal.entry.attrs.memberUid || []).join(", ")
                      : "",
                    "text",
                    false,
                  )}
                  <p className="hint">
                    Add existing usernames. POSIX GIDs are allocated
                    automatically. Host access policies will be available in
                    Milestone 2.
                  </p>
                </>
              )}
              <button className="primary" disabled={busy}>
                {busy ? "Saving…" : "Save changes"}
              </button>
            </form>
          </section>
        </div>
      )}
    </div>
  );
}
createRoot(document.getElementById("root")!).render(<App />);
