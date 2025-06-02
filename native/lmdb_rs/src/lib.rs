
use rustler::{self, types::binary::Binary, Atom, Env, ResourceArc};

rustler::atoms! {
    ok,
    error,
    not_found,
}

#[derive(Debug)]
struct EnvResource;
#[derive(Debug)]
struct TxnResource;
#[derive(Debug)]
struct CursorResource;

fn load(env: Env, _info: rustler::Term<'_>) -> bool {
    rustler::resource!(EnvResource, env);
    rustler::resource!(TxnResource, env);
    rustler::resource!(CursorResource, env);
    true
}

#[rustler::nif]
fn env_create() -> (Atom, ResourceArc<EnvResource>) {
    (ok(), ResourceArc::new(EnvResource))
}

#[rustler::nif]
fn env_open(_env: ResourceArc<EnvResource>, _path: rustler::Term<'_>, _flags: u32) -> Atom {
    ok()
}

#[rustler::nif]
fn env_close(_env: ResourceArc<EnvResource>) -> Atom {
    ok()
}

#[rustler::nif(name = "env_set_maxreaders")]
fn env_set_maxreaders(_env: ResourceArc<EnvResource>, _readers: u32) -> Atom {
    ok()
}

#[rustler::nif(name = "env_set_maxdbs")]
fn env_set_maxdbs(_env: ResourceArc<EnvResource>, _dbs: u32) -> Atom {
    ok()
}

#[rustler::nif(name = "env_set_mapsize")]
fn env_set_mapsize(_env: ResourceArc<EnvResource>, _size: u64) -> Atom {
    ok()
}

#[rustler::nif(name = "env_sync")]
fn env_sync(_env: ResourceArc<EnvResource>, _force: i32) -> Atom {
    ok()
}

#[rustler::nif(name = "env_stat")]
fn env_stat(_env: ResourceArc<EnvResource>) -> Atom {
    ok()
}

#[rustler::nif(name = "env_info")]
fn env_info(_env: ResourceArc<EnvResource>) -> Atom {
    ok()
}

#[rustler::nif(name = "txn_begin")]
fn txn_begin(
    _env: ResourceArc<EnvResource>,
    _parent: rustler::types::atom::Atom,
    _flags: u32,
) -> (Atom, ResourceArc<TxnResource>) {
    (ok(), ResourceArc::new(TxnResource))
}

#[rustler::nif(name = "txn_commit")]
fn txn_commit(_txn: ResourceArc<TxnResource>) -> Atom {
    ok()
}

#[rustler::nif(name = "txn_abort")]
fn txn_abort(_txn: ResourceArc<TxnResource>) -> Atom {
    ok()
}

#[rustler::nif(name = "dbi_open")]
fn dbi_open(_txn: ResourceArc<TxnResource>, _name: rustler::Term, _flags: u32) -> (Atom, u32) {
    // Return a fake DBI handle of 0.
    (ok(), 0)
}

#[rustler::nif(name = "dbi_close")]
fn dbi_close(_env: ResourceArc<EnvResource>, _dbi: u32) -> Atom {
    ok()
}

#[rustler::nif(name = "dbi_stat")]
fn dbi_stat(_txn: ResourceArc<TxnResource>, _dbi: u32) -> Atom {
    ok()
}

#[rustler::nif(name = "get")]
fn get(
    _txn: ResourceArc<TxnResource>,
    _dbi: u32,
    _key: Binary,
) -> Atom {
    not_found()
}

#[rustler::nif(name = "put")]
fn put(
    _txn: ResourceArc<TxnResource>,
    _dbi: u32,
    _key: Binary,
    _data: Binary,
    _flags: u32,
) -> Atom {
    ok()
}

#[rustler::nif(name = "del")]
fn del_3(
    _txn: ResourceArc<TxnResource>,
    _dbi: u32,
    _key: Binary,
) -> Atom {
    ok()
}

#[rustler::nif(name = "del")]
fn del_4(
    _txn: ResourceArc<TxnResource>,
    _dbi: u32,
    _key: Binary,
    _data: Binary,
) -> Atom {
    ok()
}

#[rustler::nif(name = "cursor_open")]
fn cursor_open(
    _txn: ResourceArc<TxnResource>,
    _dbi: u32,
) -> (Atom, ResourceArc<CursorResource>) {
    (ok(), ResourceArc::new(CursorResource))
}

#[rustler::nif(name = "cursor_close")]
fn cursor_close(_cur: ResourceArc<CursorResource>) -> Atom {
    ok()
}

#[rustler::nif(name = "cursor_get")]
fn cursor_get(
    _cur: ResourceArc<CursorResource>,
    _key: Binary,
    _op: u32,
) -> Atom {
    not_found()
}

#[rustler::nif(name = "cursor_put")]
fn cursor_put(
    _cur: ResourceArc<CursorResource>,
    _key: Binary,
    _data: Binary,
    _flags: u32,
) -> Atom {
    ok()
}

#[rustler::nif(name = "cursor_del")]
fn cursor_del(_cur: ResourceArc<CursorResource>, _flags: u32) -> Atom {
    ok()
}

rustler::init!(
    "lmdb_rs",
    load = load
);
