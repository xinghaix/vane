//! Linux RTNETLINK 地址/链路变更通知，只唤醒对账，不直接使用事件数据配置防火墙。
use tokio::sync::watch;

#[cfg(target_os="linux")]
pub async fn watch_changes(tx:watch::Sender<u64>) -> Result<(),String> {
    use std::os::fd::{AsRawFd,FromRawFd,OwnedFd};
    let raw=unsafe {libc::socket(libc::AF_NETLINK,libc::SOCK_RAW|libc::SOCK_NONBLOCK|libc::SOCK_CLOEXEC,libc::NETLINK_ROUTE)};
    if raw<0 {return Err("创建 RTNETLINK socket 失败".into());}
    let fd=unsafe {OwnedFd::from_raw_fd(raw)};
    let mut addr:libc::sockaddr_nl=unsafe {std::mem::zeroed()};
    addr.nl_family=libc::AF_NETLINK as u16;
    addr.nl_groups=1|0x10|0x100;
    if unsafe {libc::bind(fd.as_raw_fd(),&addr as *const _ as *const libc::sockaddr,std::mem::size_of_val(&addr) as libc::socklen_t)}!=0 {
        return Err("订阅 RTNETLINK 变更失败".into());
    }
    // OwnedFd 独占该描述符，注册期间不替换、不提前关闭，满足 AsyncFd 的 I/O 安全契约。
    let fd=unsafe {tokio::io::unix::AsyncFd::register(fd)}.map_err(|_|"注册 RTNETLINK socket 失败")?;
    let mut sequence=0u64;
    let mut bytes=[0u8;32768];
    loop {
        tokio::select! {
            _=tx.closed()=>return Ok(()),
            readiness=fd.readable()=>{
                let mut readiness=readiness.map_err(|_|"RTNETLINK 读取失败")?;
                let received=readiness.try_io(|inner|{
                    let n=unsafe {libc::recv(inner.get_ref().as_raw_fd(),bytes.as_mut_ptr() as *mut libc::c_void,bytes.len(),0)};
                    if n<0 {Err(std::io::Error::last_os_error())} else {Ok(n)}
                });
                match received {
                    Ok(Ok(_))=>{},
                    Ok(Err(error)) if error.raw_os_error()==Some(libc::ENOBUFS)=>{},
                    Ok(Err(_))=>return Err("RTNETLINK 消息读取失败".into()),
                    Err(_)=>continue,
                }
                sequence=sequence.wrapping_add(1);
                tx.send_replace(sequence);
            }
        }
    }
}

#[cfg(not(target_os="linux"))]
pub async fn watch_changes(tx:watch::Sender<u64>) -> Result<(),String> {
    // 非 Linux 平台使用已有定时对账；保持 sender 活跃避免忙轮询。
    tx.closed().await;
    Ok(())
}
