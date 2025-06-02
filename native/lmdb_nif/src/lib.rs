use std::{
    cell::Cell,
    ffi::{CStr, CString},
    os::raw::c_int,
    ptr,
};

use libc::{c_uint, c_void, size_t};
use liblmdb as lmdb;

use rustler::{self, types::binary::Binary, Encoder, Env, OwnedBinary, ResourceArc, Term};

rustler::atoms! {
    ok,
    error,
    not_found,
    psize,
    depth,
    branch_pages,
    leaf_pages,
    overflow_pages,
    entries,
    environment_closed,
    transaction_inactive,
    cursor_closed,
    parent_transaction_inactive,
    invalid_parent_transaction,
}

#[derive(Debug)]
struct EnvResource {
    env: Cell<*mut lmdb::MDB_env>,
}

unsafe impl Send for EnvResource {}
unsafe impl Sync for EnvResource {}

impl Drop for EnvResource {
    fn drop(&mut self) {
        let ptr = self.env.get();
        if !ptr.is_null() {
            unsafe { lmdb::mdb_env_close(ptr) };
        }
    }
}

#[derive(Debug)]
struct TxnResource {
    txn: Cell<*mut lmdb::MDB_txn>,
}

unsafe impl Send for TxnResource {}
unsafe impl Sync for TxnResource {}

impl Drop for TxnResource {
    fn drop(&mut self) {
        let ptr = self.txn.get();
        if !ptr.is_null() {
            unsafe { lmdb::mdb_txn_abort(ptr) };
        }
    }
}

#[derive(Debug)]
struct CursorResource {
    cursor: Cell<*mut lmdb::MDB_cursor>,
}

unsafe impl Send for CursorResource {}
unsafe impl Sync for CursorResource {}

impl Drop for CursorResource {
    fn drop(&mut self) {
        let ptr = self.cursor.get();
        if !ptr.is_null() {
            unsafe { lmdb::mdb_cursor_close(ptr) };
        }
    }
}

fn load(env: Env, _info: Term<'_>) -> bool {
    rustler::resource!(EnvResource, env);
    rustler::resource!(TxnResource, env);
    rustler::resource!(CursorResource, env);
    true
}

#[rustler::nif]
fn env_create<'a>(env: Env<'a>) -> Term<'a> {
    let mut env_ptr: *mut lmdb::MDB_env = ptr::null_mut();
    let rc = unsafe { lmdb::mdb_env_create(&mut env_ptr) };
    if rc != 0 {
        return rc_to_term(env, rc);
    }
    let res = ResourceArc::new(EnvResource {
        env: Cell::new(env_ptr),
    });
    make_ok_tuple(env, res)
}

#[rustler::nif]
fn env_open<'a>(
    env: Env<'a>,
    env_res: ResourceArc<EnvResource>,
    path_term: Term<'a>,
    flags: u32,
) -> Term<'a> {
    if env_res.env.get().is_null() {
        return (error(), environment_closed()).encode(env);
    }
    let path_cstr = match term_to_cstring(path_term) {
        Some(p) => p,
        None => return rustler::types::atom::error().encode(env),
    };
    let rc = unsafe {
        lmdb::mdb_env_open(
            env_res.env.get(),
            path_cstr.as_ptr(),
            flags as c_uint,
            0o664,
        )
    };
    rc_to_term(env, rc)
}

#[rustler::nif]
fn env_close<'a>(env: Env<'a>, env_res: ResourceArc<EnvResource>) -> Term<'a> {
    // Drop happens automatically, but we set pointer to null so double close avoided
    let mut_env = ResourceArc::clone(&env_res);
    unsafe {
        lmdb::mdb_env_close(mut_env.env.get());
        // Note: don't free env; pointer freed by LMDB
        mut_env.env.set(ptr::null_mut());
    }
    ok().encode(env)
}

#[rustler::nif]
fn env_set_maxreaders<'a>(
    env: Env<'a>,
    env_res: ResourceArc<EnvResource>,
    readers: u32,
) -> Term<'a> {
    if env_res.env.get().is_null() {
        return (error(), environment_closed()).encode(env);
    }
    let rc = unsafe { lmdb::mdb_env_set_maxreaders(env_res.env.get(), readers as c_uint) };
    rc_to_term(env, rc)
}

#[rustler::nif]
fn env_set_maxdbs<'a>(env: Env<'a>, env_res: ResourceArc<EnvResource>, dbs: u32) -> Term<'a> {
    if env_res.env.get().is_null() {
        return (error(), environment_closed()).encode(env);
    }
    let rc = unsafe { lmdb::mdb_env_set_maxdbs(env_res.env.get(), dbs as c_uint) };
    rc_to_term(env, rc)
}

#[rustler::nif]
fn env_set_mapsize<'a>(env: Env<'a>, env_res: ResourceArc<EnvResource>, size: u64) -> Term<'a> {
    if env_res.env.get().is_null() {
        return (error(), environment_closed()).encode(env);
    }
    let rc = unsafe { lmdb::mdb_env_set_mapsize(env_res.env.get(), size as size_t) };
    rc_to_term(env, rc)
}

#[rustler::nif]
fn env_sync<'a>(env: Env<'a>, env_res: ResourceArc<EnvResource>, force: i32) -> Term<'a> {
    if env_res.env.get().is_null() {
        return (error(), environment_closed()).encode(env);
    }
    let rc = unsafe { lmdb::mdb_env_sync(env_res.env.get(), force) };
    rc_to_term(env, rc)
}

#[rustler::nif]
fn env_stat<'a>(env: Env<'a>, env_res: ResourceArc<EnvResource>) -> Term<'a> {
    if env_res.env.get().is_null() {
        return (error(), environment_closed()).encode(env);
    }
    unsafe {
        let mut stat = std::mem::MaybeUninit::<lmdb::MDB_stat>::uninit();
        let rc = lmdb::mdb_env_stat(env_res.env.get(), stat.as_mut_ptr());
        if rc != 0 {
            return rc_to_term(env, rc);
        }
        let stat = stat.assume_init();
        let list = vec![
            (psize(), stat.ms_psize as u64).encode(env),
            (depth(), stat.ms_depth as u64).encode(env),
            (branch_pages(), stat.ms_branch_pages as u64).encode(env),
            (leaf_pages(), stat.ms_leaf_pages as u64).encode(env),
            (overflow_pages(), stat.ms_overflow_pages as u64).encode(env),
            (entries(), stat.ms_entries as u64).encode(env),
        ];
        make_ok_tuple(env, list)
    }
}

#[rustler::nif]
fn env_info<'a>(env: Env<'a>, env_res: ResourceArc<EnvResource>) -> Term<'a> {
    if env_res.env.get().is_null() {
        return (error(), environment_closed()).encode(env);
    }
    unsafe {
        let mut info = std::mem::MaybeUninit::<lmdb::MDB_envinfo>::uninit();
        let rc = lmdb::mdb_env_info(env_res.env.get(), info.as_mut_ptr());
        if rc != 0 {
            return rc_to_term(env, rc);
        }
        let info = info.assume_init();
        let list = vec![
            ("mapaddr", info.me_mapaddr as u64),
            ("mapsize", info.me_mapsize as u64),
            ("last_pgno", info.me_last_pgno as u64),
            ("last_txnid", info.me_last_txnid as u64),
            ("maxreaders", info.me_maxreaders as u64),
            ("numreaders", info.me_numreaders as u64),
        ];
        make_ok_tuple(env, list)
    }
}

#[rustler::nif]
fn txn_begin<'a>(
    env: Env<'a>,
    env_res: ResourceArc<EnvResource>,
    parent: Term<'a>,
    flags: u32,
) -> Term<'a> {
    if env_res.env.get().is_null() {
        return (error(), environment_closed()).encode(env);
    }
    let mut parent_txn_ptr: *mut lmdb::MDB_txn = ptr::null_mut();
    if !parent.is_atom() {
        match parent.decode::<ResourceArc<TxnResource>>() {
            Ok(res_arc) => {
                parent_txn_ptr = res_arc.txn.get();
                if parent_txn_ptr.is_null() {
                    return (error(), parent_transaction_inactive()).encode(env);
                }
            }
            Err(_) => {
                return (error(), invalid_parent_transaction()).encode(env);
            }
        }
    }
    let mut txn_ptr: *mut lmdb::MDB_txn = ptr::null_mut();
    let rc = unsafe {
        lmdb::mdb_txn_begin(
            env_res.env.get(),
            parent_txn_ptr,
            flags as c_uint,
            &mut txn_ptr,
        )
    };
    if rc != 0 {
        return rc_to_term(env, rc);
    }
    let res = ResourceArc::new(TxnResource {
        txn: Cell::new(txn_ptr),
    });
    make_ok_tuple(env, res)
}

#[rustler::nif]
fn txn_commit<'a>(env: Env<'a>, txn_res: ResourceArc<TxnResource>) -> Term<'a> {
    if txn_res.txn.get().is_null() {
        return (error(), transaction_inactive()).encode(env);
    }
    let rc = unsafe { lmdb::mdb_txn_commit(txn_res.txn.get()) };
    // After commit, txn handle is invalid; set pointer to null
    let mut_ref = ResourceArc::clone(&txn_res);
    mut_ref.txn.set(ptr::null_mut());
    rc_to_term(env, rc)
}

#[rustler::nif]
fn txn_abort<'a>(env: Env<'a>, txn_res: ResourceArc<TxnResource>) -> Term<'a> {
    unsafe {
        if !txn_res.txn.get().is_null() {
            lmdb::mdb_txn_abort(txn_res.txn.get());
            let mut_ref = ResourceArc::clone(&txn_res);
            mut_ref.txn.set(ptr::null_mut());
        }
    }
    ok().encode(env)
}

#[rustler::nif]
fn dbi_open<'a>(
    env: Env<'a>,
    txn_res: ResourceArc<TxnResource>,
    name_term: Term<'a>,
    flags: u32,
) -> Term<'a> {
    if txn_res.txn.get().is_null() {
        return (error(), transaction_inactive()).encode(env);
    }
    let name_ptr: *const libc::c_char;
    let c_name;
    if name_term.is_atom() {
        name_ptr = ptr::null();
    } else {
        c_name = match term_to_cstring(name_term) {
            Some(c) => c,
            None => return rustler::types::atom::error().encode(env),
        };
        name_ptr = c_name.as_ptr();
    }

    let mut dbi: lmdb::MDB_dbi = 0;
    let mut open_flags = flags as c_uint;
    if name_ptr.is_null() {
        open_flags &= !(lmdb::MDB_CREATE as c_uint);
    }
    let rc = unsafe { lmdb::mdb_dbi_open(txn_res.txn.get(), name_ptr, open_flags, &mut dbi) };
    if rc != 0 {
        return rc_to_term(env, rc);
    }

    make_ok_tuple(env, dbi as u32)
}

#[rustler::nif]
fn dbi_close<'a>(env: Env<'a>, env_res: ResourceArc<EnvResource>, dbi: u32) -> Term<'a> {
    if env_res.env.get().is_null() {
        return (error(), environment_closed()).encode(env);
    }
    unsafe { lmdb::mdb_dbi_close(env_res.env.get(), dbi as lmdb::MDB_dbi) };
    ok().encode(env)
}

#[rustler::nif]
fn dbi_stat<'a>(env: Env<'a>, txn_res: ResourceArc<TxnResource>, dbi: u32) -> Term<'a> {
    if txn_res.txn.get().is_null() {
        return (error(), transaction_inactive()).encode(env);
    }
    unsafe {
        let mut stat = std::mem::MaybeUninit::<lmdb::MDB_stat>::uninit();
        let rc = lmdb::mdb_stat(txn_res.txn.get(), dbi as lmdb::MDB_dbi, stat.as_mut_ptr());
        if rc != 0 {
            return rc_to_term(env, rc);
        }
        let stat = stat.assume_init();
        let list = vec![
            (psize(), stat.ms_psize as u64).encode(env),
            (depth(), stat.ms_depth as u64).encode(env),
            (branch_pages(), stat.ms_branch_pages as u64).encode(env),
            (leaf_pages(), stat.ms_leaf_pages as u64).encode(env),
            (overflow_pages(), stat.ms_overflow_pages as u64).encode(env),
            (entries(), stat.ms_entries as u64).encode(env),
        ];
        make_ok_tuple(env, list)
    }
}

#[rustler::nif]
fn get<'a>(
    env: Env<'a>,
    txn_res: ResourceArc<TxnResource>,
    dbi: u32,
    key_bin: Binary<'a>,
) -> Term<'a> {
    if txn_res.txn.get().is_null() {
        return (error(), transaction_inactive()).encode(env);
    }
    let mut key = lmdb::MDB_val {
        mv_size: key_bin.len() as size_t,
        mv_data: key_bin.as_ptr() as *mut c_void,
    };
    let mut data = lmdb::MDB_val {
        mv_size: 0,
        mv_data: ptr::null_mut(),
    };
    let rc = unsafe { lmdb::mdb_get(txn_res.txn.get(), dbi as lmdb::MDB_dbi, &mut key, &mut data) };
    if rc == lmdb::MDB_NOTFOUND {
        return not_found().encode(env);
    } else if rc != 0 {
        return rc_to_term(env, rc);
    }
    let slice =
        unsafe { std::slice::from_raw_parts(data.mv_data as *const u8, data.mv_size as usize) };
    let mut owned = OwnedBinary::new(slice.len()).unwrap();
    owned.as_mut_slice().copy_from_slice(slice);
    let bin_term = owned.release(env);
    make_ok_tuple(env, bin_term)
}

#[rustler::nif]
fn put<'a>(
    env: Env<'a>,
    txn_res: ResourceArc<TxnResource>,
    dbi: u32,
    key_bin: Binary<'a>,
    data_bin: Binary<'a>,
    flags: u32,
) -> Term<'a> {
    if txn_res.txn.get().is_null() {
        return (error(), transaction_inactive()).encode(env);
    }
    let mut key = lmdb::MDB_val {
        mv_size: key_bin.len() as size_t,
        mv_data: key_bin.as_ptr() as *mut c_void,
    };
    let mut data = lmdb::MDB_val {
        mv_size: data_bin.len() as size_t,
        mv_data: data_bin.as_ptr() as *mut c_void,
    };
    let rc = unsafe {
        lmdb::mdb_put(
            txn_res.txn.get(),
            dbi as lmdb::MDB_dbi,
            &mut key,
            &mut data,
            flags as c_uint,
        )
    };
    rc_to_term(env, rc)
}

#[rustler::nif(name = "del")]
fn del_3<'a>(
    env: Env<'a>,
    txn_res: ResourceArc<TxnResource>,
    dbi: u32,
    key_bin: Binary<'a>,
) -> Term<'a> {
    if txn_res.txn.get().is_null() {
        return (error(), transaction_inactive()).encode(env);
    }
    let mut key = lmdb::MDB_val {
        mv_size: key_bin.len() as size_t,
        mv_data: key_bin.as_ptr() as *mut c_void,
    };
    let rc = unsafe {
        lmdb::mdb_del(
            txn_res.txn.get(),
            dbi as lmdb::MDB_dbi,
            &mut key,
            ptr::null_mut(),
        )
    };
    if rc == lmdb::MDB_NOTFOUND {
        return not_found().encode(env);
    }
    rc_to_term(env, rc)
}

#[rustler::nif(name = "del")]
fn del_4<'a>(
    env: Env<'a>,
    txn_res: ResourceArc<TxnResource>,
    dbi: u32,
    key_bin: Binary<'a>,
    data_bin: Binary<'a>,
) -> Term<'a> {
    if txn_res.txn.get().is_null() {
        return (error(), transaction_inactive()).encode(env);
    }
    let mut key = lmdb::MDB_val {
        mv_size: key_bin.len() as size_t,
        mv_data: key_bin.as_ptr() as *mut c_void,
    };
    let mut data = lmdb::MDB_val {
        mv_size: data_bin.len() as size_t,
        mv_data: data_bin.as_ptr() as *mut c_void,
    };
    let rc = unsafe { lmdb::mdb_del(txn_res.txn.get(), dbi as lmdb::MDB_dbi, &mut key, &mut data) };
    if rc == lmdb::MDB_NOTFOUND {
        return not_found().encode(env);
    }
    rc_to_term(env, rc)
}

#[rustler::nif]
fn cursor_open<'a>(env: Env<'a>, txn_res: ResourceArc<TxnResource>, dbi: u32) -> Term<'a> {
    if txn_res.txn.get().is_null() {
        return (error(), transaction_inactive()).encode(env);
    }
    let mut cursor_ptr: *mut lmdb::MDB_cursor = ptr::null_mut();
    let rc =
        unsafe { lmdb::mdb_cursor_open(txn_res.txn.get(), dbi as lmdb::MDB_dbi, &mut cursor_ptr) };
    if rc != 0 {
        return rc_to_term(env, rc);
    }
    let res = ResourceArc::new(CursorResource {
        cursor: Cell::new(cursor_ptr),
    });
    make_ok_tuple(env, res)
}

#[rustler::nif]
fn cursor_close<'a>(env: Env<'a>, cur_res: ResourceArc<CursorResource>) -> Term<'a> {
    if cur_res.cursor.get().is_null() {
        return (error(), cursor_closed()).encode(env);
    }
    unsafe {
        lmdb::mdb_cursor_close(cur_res.cursor.get());
        let mut_ref = ResourceArc::clone(&cur_res);
        mut_ref.cursor.set(ptr::null_mut());
    }
    ok().encode(env)
}

#[rustler::nif]
fn cursor_get<'a>(
    env: Env<'a>,
    cur_res: ResourceArc<CursorResource>,
    key_bin: Binary<'a>,
    op: u32,
) -> Term<'a> {
    if cur_res.cursor.get().is_null() {
        return (error(), cursor_closed()).encode(env);
    }
    let mut key = lmdb::MDB_val {
        mv_size: key_bin.len() as size_t,
        mv_data: key_bin.as_ptr() as *mut c_void,
    };
    let mut data = lmdb::MDB_val {
        mv_size: 0,
        mv_data: ptr::null_mut(),
    };
    let rc = unsafe {
        lmdb::mdb_cursor_get(
            cur_res.cursor.get(),
            &mut key,
            &mut data,
            op as lmdb::MDB_cursor_op,
        )
    };
    if rc == lmdb::MDB_NOTFOUND {
        return not_found().encode(env);
    } else if rc != 0 {
        return rc_to_term(env, rc);
    }
    // Copy key and data into binaries
    let key_slice =
        unsafe { std::slice::from_raw_parts(key.mv_data as *const u8, key.mv_size as usize) };
    let data_slice =
        unsafe { std::slice::from_raw_parts(data.mv_data as *const u8, data.mv_size as usize) };
    let mut key_owned = OwnedBinary::new(key_slice.len()).unwrap();
    key_owned.as_mut_slice().copy_from_slice(key_slice);
    let key_term = key_owned.release(env);

    let mut data_owned = OwnedBinary::new(data_slice.len()).unwrap();
    data_owned.as_mut_slice().copy_from_slice(data_slice);
    let data_term = data_owned.release(env);

    (ok(), key_term, data_term).encode(env)
}

#[rustler::nif]
fn cursor_put<'a>(
    env: Env<'a>,
    cur_res: ResourceArc<CursorResource>,
    key_bin: Binary<'a>,
    data_bin: Binary<'a>,
    flags: u32,
) -> Term<'a> {
    if cur_res.cursor.get().is_null() {
        return (error(), cursor_closed()).encode(env);
    }
    let mut key = lmdb::MDB_val {
        mv_size: key_bin.len() as size_t,
        mv_data: key_bin.as_ptr() as *mut c_void,
    };
    let mut data = lmdb::MDB_val {
        mv_size: data_bin.len() as size_t,
        mv_data: data_bin.as_ptr() as *mut c_void,
    };
    let rc =
        unsafe { lmdb::mdb_cursor_put(cur_res.cursor.get(), &mut key, &mut data, flags as c_uint) };
    rc_to_term(env, rc)
}

#[rustler::nif]
fn cursor_del<'a>(env: Env<'a>, cur_res: ResourceArc<CursorResource>, flags: u32) -> Term<'a> {
    if cur_res.cursor.get().is_null() {
        return (error(), cursor_closed()).encode(env);
    }
    let rc = unsafe { lmdb::mdb_cursor_del(cur_res.cursor.get(), flags as c_uint) };
    rc_to_term(env, rc)
}

// === Helpers ===========================================================

fn rc_to_term<'a>(env: Env<'a>, rc: c_int) -> Term<'a> {
    if rc == lmdb::MDB_SUCCESS as c_int {
        ok().encode(env)
    } else if rc == lmdb::MDB_NOTFOUND as c_int {
        not_found().encode(env)
    } else {
        let c_str = unsafe { CStr::from_ptr(lmdb::mdb_strerror(rc)) };
        let msg = c_str.to_string_lossy();
        (error(), msg.as_ref()).encode(env)
    }
}

/// Convert an Erlang term that may be a binary, charlist, or string into a CString
fn term_to_cstring<'a>(term: Term<'a>) -> Option<CString> {
    // Binary case
    if let Ok(bin) = term.decode::<Binary>() {
        return CString::new(bin.as_slice()).ok();
    }
    // List of integers (charlist)
    if let Ok(list) = term.decode::<Vec<u8>>() {
        return CString::new(list).ok();
    }
    if let Ok(string) = term.decode::<String>() {
        return CString::new(string).ok();
    }
    None
}

fn make_ok_tuple<'b, T: rustler::Encoder + 'b>(env: Env<'b>, value: T) -> Term<'b> {
    (ok(), value).encode(env)
}

rustler::init!("lmdb_nif", load = load);
