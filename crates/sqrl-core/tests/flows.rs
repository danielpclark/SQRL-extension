//! End-to-end protocol flows between `Session` (client) and `ReferenceServer`.

use sqrl_core::identity::UnlockedIdentity;
use sqrl_core::protocol::{Ask, AskButton, ClientOptions, Command, SessionState, Tif};
use sqrl_core::server::ReferenceServer;
use sqrl_core::url::{query_pairs, SqrlUrl};
use sqrl_core::util::b64u_encode;
use sqrl_core::Session;

const IP: &str = "203.0.113.7";

/// Simulate the HTTPS transport: pull the nut from the POST URL and hand the body to the server.
fn post(server: &mut ReferenceServer, req: &sqrl_core::protocol::Request, ip: &str) -> String {
    assert!(
        req.url.starts_with("https://example.com/cli.sqrl?"),
        "{}",
        req.url
    );
    let query = req.url.split_once('?').unwrap().1;
    let nut = query_pairs(query)
        .into_iter()
        .find(|(k, _)| k == "nut")
        .map(|(_, v)| v)
        .unwrap();
    server.handle(&nut, &req.body, ip)
}

fn new_session(
    server: &mut ReferenceServer,
    identity: &UnlockedIdentity,
    options: ClientOptions,
) -> (String, Session) {
    let (sid, url) = server.new_login_url(IP, Some("/cancelled"));
    let url = SqrlUrl::parse(&url).unwrap();
    (sid, Session::new(identity.clone(), url, options, None))
}

fn exchange(
    server: &mut ReferenceServer,
    session: &mut Session,
    req: sqrl_core::protocol::Request,
) -> Tif {
    let body = post(server, &req, IP);
    session.feed(&body).unwrap().tif
}

#[test]
fn create_account_then_login_with_cps() {
    let mut server = ReferenceServer::new("example.com", "/cli.sqrl");
    let identity = UnlockedIdentity::from_iuk(&[1u8; 32]);
    let opts = ClientOptions {
        cps: true,
        ..Default::default()
    };

    // First visit: unknown identity → create the account.
    let (sid, mut s) = new_session(&mut server, &identity, opts);
    let q = s.query().unwrap();
    assert_eq!(q.command, Command::Query);
    let tif = exchange(&mut server, &mut s, q);
    assert!(!tif.id_match());
    assert!(tif.ips_matched());
    assert_eq!(s.state(), SessionState::Unknown);
    let ident = s.ident().unwrap();
    assert!(ident.client_text.contains("suk="));
    assert!(ident.client_text.contains("vuk="));
    assert!(ident.client_text.contains("opt=cps"));
    let tif = exchange(&mut server, &mut s, ident);
    assert!(tif.id_match());
    assert_eq!(s.state(), SessionState::Known { disabled: false });
    assert_eq!(server.session(&sid).unwrap().authenticated, Some(s.idk()));
    let cps = s.cps_url().unwrap().unwrap();
    assert_eq!(cps, format!("https://example.com/loggedin?session={sid}"));
    assert_eq!(
        s.cancel_url().as_deref(),
        Some("https://example.com/cancelled")
    );
    assert_eq!(server.account_count(), 1);

    // Second visit: known identity → plain login, no suk/vuk needed.
    let (sid2, mut s2) = new_session(&mut server, &identity, opts);
    let q = s2.query().unwrap();
    let tif = exchange(&mut server, &mut s2, q);
    assert!(tif.id_match());
    // suk was requested by the query, so the server returned it
    assert!(s2.last_response().unwrap().suk.is_some());
    let ident = s2.ident().unwrap();
    assert!(!ident.client_text.contains("suk="));
    let tif = exchange(&mut server, &mut s2, ident);
    assert!(tif.id_match() && !tif.is_error());
    assert_eq!(server.session(&sid2).unwrap().authenticated, Some(s2.idk()));
    assert_eq!(server.account(&s2.idk()).unwrap().logins, 2);
}

#[test]
fn disable_enable_remove_with_rescue_code() {
    let mut server = ReferenceServer::new("example.com", "/cli.sqrl");
    let iuk = [2u8; 32];
    let identity = UnlockedIdentity::from_iuk(&iuk);

    // create
    let (_, mut s) = new_session(&mut server, &identity, ClientOptions::default());
    let q = s.query().unwrap();
    exchange(&mut server, &mut s, q);
    let i = s.ident().unwrap();
    exchange(&mut server, &mut s, i);

    // disable
    let (_, mut s) = new_session(&mut server, &identity, ClientOptions::default());
    let q = s.query().unwrap();
    exchange(&mut server, &mut s, q);
    let d = s.disable().unwrap();
    let tif = exchange(&mut server, &mut s, d);
    assert!(tif.sqrl_disabled() && !tif.is_error());
    assert!(server.account(&s.idk()).unwrap().disabled);

    // login now fails
    let (sid, mut s) = new_session(&mut server, &identity, ClientOptions::default());
    let q = s.query().unwrap();
    exchange(&mut server, &mut s, q);
    assert_eq!(s.state(), SessionState::Known { disabled: true });
    let i = s.ident().unwrap();
    let tif = exchange(&mut server, &mut s, i);
    assert!(tif.command_failed());
    assert!(server.session(&sid).unwrap().authenticated.is_none());

    // enable needs the IUK
    let (_, mut s) = new_session(&mut server, &identity, ClientOptions::default());
    let q = s.query().unwrap();
    exchange(&mut server, &mut s, q);
    assert!(s.enable(None).is_err());
    // wrong IUK → signature does not verify
    let bad = s.enable(Some(&[3u8; 32])).unwrap();
    let tif = exchange(&mut server, &mut s, bad);
    assert!(tif.command_failed());
    assert!(server.account(&s.idk()).unwrap().disabled);

    let (_, mut s) = new_session(&mut server, &identity, ClientOptions::default());
    let q = s.query().unwrap();
    exchange(&mut server, &mut s, q);
    let e = s.enable(Some(&iuk)).unwrap();
    assert!(e.body.contains("&urs="));
    let tif = exchange(&mut server, &mut s, e);
    assert!(!tif.sqrl_disabled() && !tif.is_error());
    assert!(!server.account(&s.idk()).unwrap().disabled);

    // remove
    let (_, mut s) = new_session(&mut server, &identity, ClientOptions::default());
    let q = s.query().unwrap();
    exchange(&mut server, &mut s, q);
    let r = s.remove(Some(&iuk)).unwrap();
    let tif = exchange(&mut server, &mut s, r);
    assert!(!tif.id_match() && !tif.is_error());
    assert_eq!(server.account_count(), 0);
}

#[test]
fn rekey_moves_account_to_new_identity() {
    let mut server = ReferenceServer::new("example.com", "/cli.sqrl");
    let old_iuk = [4u8; 32];
    let old = UnlockedIdentity::from_iuk(&old_iuk);
    let (_, mut s) = new_session(&mut server, &old, ClientOptions::default());
    let q = s.query().unwrap();
    exchange(&mut server, &mut s, q);
    let i = s.ident().unwrap();
    exchange(&mut server, &mut s, i);
    let old_idk = s.idk();

    // Re-keyed identity carries the old IUK as a previous identity.
    let mut new = UnlockedIdentity::from_iuk(&[5u8; 32]);
    new.previous_iuks.push(old_iuk);
    let (sid, mut s) = new_session(&mut server, &new, ClientOptions::default());
    let q = s.query().unwrap();
    assert!(q.client_text.contains("pidk="));
    assert!(q.body.contains("&pids="));
    let tif = exchange(&mut server, &mut s, q);
    assert!(tif.previous_id_match() && !tif.id_match());
    assert_eq!(s.state(), SessionState::PreviousKnown { disabled: false });
    assert!(s.last_response().unwrap().suk.is_some());
    let i = s.ident().unwrap();
    assert!(
        i.client_text.contains("pidk=")
            && i.client_text.contains("suk=")
            && i.client_text.contains("vuk=")
    );
    assert!(i.body.contains("&pids=") && i.body.contains("&urs="));
    let tif = exchange(&mut server, &mut s, i);
    assert!(tif.id_match() && !tif.is_error());
    assert_eq!(server.session(&sid).unwrap().authenticated, Some(s.idk()));
    assert!(server.account(&s.idk()).is_some());
    assert!(server.account(&old_idk).is_none());
    assert!(server.is_superseded(&old_idk));

    // The old identity is now superseded.
    let (_, mut s) = new_session(&mut server, &old, ClientOptions::default());
    let q = s.query().unwrap();
    let tif = exchange(&mut server, &mut s, q);
    assert!(tif.identity_superseded());
    assert_eq!(s.state(), SessionState::Superseded);

    // The new identity logs in normally from now on, without re-keying.
    let (_, mut s) = new_session(&mut server, &new, ClientOptions::default());
    let q = s.query().unwrap();
    let tif = exchange(&mut server, &mut s, q);
    assert!(tif.id_match());
    let i = s.ident().unwrap();
    assert!(!i.client_text.contains("suk="));
    let tif = exchange(&mut server, &mut s, i);
    assert!(!tif.is_error());
}

#[test]
fn older_previous_identities_are_tried_in_turn() {
    let mut server = ReferenceServer::new("example.com", "/cli.sqrl");
    let oldest_iuk = [6u8; 32];
    let oldest = UnlockedIdentity::from_iuk(&oldest_iuk);
    let (_, mut s) = new_session(&mut server, &oldest, ClientOptions::default());
    let q = s.query().unwrap();
    exchange(&mut server, &mut s, q);
    let i = s.ident().unwrap();
    exchange(&mut server, &mut s, i);

    // identity re-keyed twice since: previous = [middle, oldest]
    let mut current = UnlockedIdentity::from_iuk(&[8u8; 32]);
    current.previous_iuks = vec![[7u8; 32], oldest_iuk];
    let (_, mut s) = new_session(&mut server, &current, ClientOptions::default());
    let q = s.query().unwrap();
    let tif = exchange(&mut server, &mut s, q);
    assert_eq!(s.state(), SessionState::Unknown);
    assert!(!tif.previous_id_match());
    assert!(s.try_next_previous());
    let q = s.query().unwrap();
    let tif = exchange(&mut server, &mut s, q);
    assert!(tif.previous_id_match());
    assert!(!s.try_next_previous());
    let i = s.ident().unwrap();
    let tif = exchange(&mut server, &mut s, i);
    assert!(tif.id_match() && !tif.is_error());
    assert!(server.account(&s.idk()).is_some());
}

#[test]
fn enable_and_remove_via_previous_identity_do_not_need_rescue_code() {
    let mut server = ReferenceServer::new("example.com", "/cli.sqrl");
    let old_iuk = [9u8; 32];
    let old = UnlockedIdentity::from_iuk(&old_iuk);
    let (_, mut s) = new_session(&mut server, &old, ClientOptions::default());
    let q = s.query().unwrap();
    exchange(&mut server, &mut s, q);
    let i = s.ident().unwrap();
    exchange(&mut server, &mut s, i);
    let (_, mut s) = new_session(&mut server, &old, ClientOptions::default());
    let q = s.query().unwrap();
    exchange(&mut server, &mut s, q);
    let d = s.disable().unwrap();
    exchange(&mut server, &mut s, d);

    let mut new = UnlockedIdentity::from_iuk(&[10u8; 32]);
    new.previous_iuks.push(old_iuk);
    let (_, mut s) = new_session(&mut server, &new, ClientOptions::default());
    let q = s.query().unwrap();
    let tif = exchange(&mut server, &mut s, q);
    assert_eq!(s.state(), SessionState::PreviousKnown { disabled: true });
    assert!(tif.sqrl_disabled());
    let e = s.enable(None).unwrap();
    let tif = exchange(&mut server, &mut s, e);
    assert!(tif.id_match() && !tif.sqrl_disabled() && !tif.is_error());
    let acct = server.account(&s.idk()).unwrap();
    assert!(!acct.disabled);

    let (_, mut s) = new_session(&mut server, &new, ClientOptions::default());
    let q = s.query().unwrap();
    exchange(&mut server, &mut s, q);
    // now a current match: remove needs the new IUK
    assert!(s.remove(None).is_err());
    let r = s.remove(Some(&[10u8; 32])).unwrap();
    let tif = exchange(&mut server, &mut s, r);
    assert!(!tif.is_error());
    assert_eq!(server.account_count(), 0);
}

#[test]
fn ask_and_btn() {
    let mut server = ReferenceServer::new("example.com", "/cli.sqrl");
    server.ask = Some(Ask {
        message: "Create an account on example.com?".into(),
        buttons: vec![
            AskButton {
                label: "Yes".into(),
                url: None,
            },
            AskButton {
                label: "No".into(),
                url: None,
            },
        ],
    });
    let identity = UnlockedIdentity::from_iuk(&[11u8; 32]);
    // An ask is only valid once the server recognises the current identity, so create the
    // account first; no question is posed to an unknown identity.
    let (_, mut s) = new_session(&mut server, &identity, ClientOptions::default());
    let q = s.query().unwrap();
    exchange(&mut server, &mut s, q);
    assert!(s.pending_ask().is_none());
    let i = s.ident().unwrap();
    let tif = exchange(&mut server, &mut s, i);
    assert!(tif.id_match());

    let (sid, mut s) = new_session(&mut server, &identity, ClientOptions::default());
    let q = s.query().unwrap();
    exchange(&mut server, &mut s, q);
    let ask = s.pending_ask().unwrap().clone();
    assert_eq!(ask.message, "Create an account on example.com?");
    assert_eq!(ask.buttons.len(), 2);
    // Without an answer the server refuses to proceed.
    let i = s.ident().unwrap();
    assert!(!i.client_text.contains("btn="));
    let tif = exchange(&mut server, &mut s, i);
    assert!(tif.command_failed());
    // Answer and re-query.
    s.set_button(2);
    assert!(s.pending_ask().is_none());
    let q = s.query().unwrap();
    assert!(q.client_text.contains("btn=2\r\n"));
    exchange(&mut server, &mut s, q);
    assert!(s.pending_ask().is_none());
    assert_eq!(server.session(&sid).unwrap().btn, Some(2));
    let i = s.ident().unwrap();
    let tif = exchange(&mut server, &mut s, i);
    assert!(tif.id_match() && !tif.is_error());
}

#[test]
fn sin_and_ins() {
    let mut server = ReferenceServer::new("example.com", "/cli.sqrl");
    server.sin = Some("0".into());
    let identity = UnlockedIdentity::from_iuk(&[12u8; 32]);
    let (_, mut s) = new_session(&mut server, &identity, ClientOptions::default());
    let q = s.query().unwrap();
    exchange(&mut server, &mut s, q);
    let i = s.ident().unwrap();
    assert!(i.client_text.contains("ins="));
    exchange(&mut server, &mut s, i);
    let ins1 = server.account(&s.idk()).unwrap().ins.clone().unwrap();

    // The same identity produces the same indexed secret next time.
    let (_, mut s) = new_session(&mut server, &identity, ClientOptions::default());
    let q = s.query().unwrap();
    exchange(&mut server, &mut s, q);
    let i = s.ident().unwrap();
    let tif = exchange(&mut server, &mut s, i);
    assert!(!tif.is_error());
    assert_eq!(server.account(&s.idk()).unwrap().ins.as_ref(), Some(&ins1));

    // pins accompanies pidk when a previous identity is offered.
    let mut new = UnlockedIdentity::from_iuk(&[13u8; 32]);
    new.previous_iuks.push([12u8; 32]);
    let (_, mut s) = new_session(&mut server, &new, ClientOptions::default());
    let q = s.query().unwrap();
    exchange(&mut server, &mut s, q);
    let i = s.ident().unwrap();
    assert!(i.client_text.contains("ins=") && i.client_text.contains("pins="));
    let tif = exchange(&mut server, &mut s, i);
    assert!(!tif.is_error());
}

#[test]
fn transient_error_recovers_with_fresh_query() {
    let mut server = ReferenceServer::new("example.com", "/cli.sqrl");
    let identity = UnlockedIdentity::from_iuk(&[14u8; 32]);
    let (_, mut s) = new_session(&mut server, &identity, ClientOptions::default());
    let q = s.query().unwrap();
    // Replay the same request twice: the second use of the nut is a transient error.
    let body = post(&mut server, &q, IP);
    s.feed(&body).unwrap();
    let body2 = server.handle("nope", &q.body, IP);
    s.feed(&body2).unwrap();
    assert_eq!(s.state(), SessionState::Transient);
    // A new query built on that response works.
    let q = s.query().unwrap();
    let tif = exchange(&mut server, &mut s, q);
    assert!(!tif.is_error());
}

#[test]
fn tampering_is_detected() {
    let mut server = ReferenceServer::new("example.com", "/cli.sqrl");
    let identity = UnlockedIdentity::from_iuk(&[15u8; 32]);
    let (_, mut s) = new_session(&mut server, &identity, ClientOptions::default());
    let q = s.query().unwrap();
    let nut = query_pairs(q.url.split_once('?').unwrap().1)
        .into_iter()
        .find(|(k, _)| k == "nut")
        .unwrap()
        .1;

    // Modified server parameter → client failure.
    let bad_server = b64u_encode(b"sqrl://example.com/cli.sqrl?nut=other");
    let tampered = q.body.replace(
        &q.body
            .split("&server=")
            .nth(1)
            .unwrap()
            .split('&')
            .next()
            .unwrap()
            .to_string(),
        &bad_server,
    );
    let resp = server.handle(&nut, &tampered, IP);
    s.feed(&resp).unwrap();
    assert!(matches!(s.state(), SessionState::Failed(_)));

    // Corrupted signature → client failure.
    let (_, mut s) = new_session(&mut server, &identity, ClientOptions::default());
    let q = s.query().unwrap();
    let nut = query_pairs(q.url.split_once('?').unwrap().1)
        .into_iter()
        .find(|(k, _)| k == "nut")
        .unwrap()
        .1;
    let mut body = q.body.clone();
    let l = body.len();
    body.replace_range(l - 1..l, if body.ends_with('A') { "B" } else { "A" });
    let resp = server.handle(&nut, &body, IP);
    let tif = s.feed(&resp).unwrap().tif;
    assert!(tif.client_failure());

    // Response steering the client to another host is rejected by the client.
    let (_, mut s) = new_session(&mut server, &identity, ClientOptions::default());
    let evil =
        b64u_encode(b"ver=1\r\nnut=x\r\ntif=0\r\nqry=https://evil.example/cli.sqrl?nut=x\r\n");
    assert!(s.feed(&evil).is_err());
    let evil = b64u_encode(b"ver=1\r\nnut=x\r\ntif=0\r\nqry=//evil.example/cli.sqrl?nut=x\r\n");
    assert!(s.feed(&evil).is_err());

    // CPS url on another host is rejected.
    let evil = b64u_encode(
        b"ver=1\r\nnut=x\r\ntif=1\r\nqry=/cli.sqrl?nut=x\r\nurl=https://evil.example/\r\n",
    );
    s.feed(&evil).unwrap();
    assert!(s.cps_url().is_err());
}

#[test]
fn ip_mismatch_is_refused_unless_noiptest() {
    let mut server = ReferenceServer::new("example.com", "/cli.sqrl");
    let identity = UnlockedIdentity::from_iuk(&[16u8; 32]);
    let (_, mut s) = new_session(&mut server, &identity, ClientOptions::default());
    let q = s.query().unwrap();
    let body = post(&mut server, &q, "198.51.100.1");
    let tif = s.feed(&body).unwrap().tif;
    assert!(!tif.ips_matched() && tif.command_failed());

    let (_, mut s) = new_session(
        &mut server,
        &identity,
        ClientOptions {
            noiptest: true,
            ..Default::default()
        },
    );
    let q = s.query().unwrap();
    let body = post(&mut server, &q, "198.51.100.1");
    let tif = s.feed(&body).unwrap().tif;
    assert!(!tif.ips_matched() && !tif.is_error());
}

#[test]
fn different_identity_mid_session_is_bad_association() {
    let mut server = ReferenceServer::new("example.com", "/cli.sqrl");
    let a = UnlockedIdentity::from_iuk(&[17u8; 32]);
    let b = UnlockedIdentity::from_iuk(&[18u8; 32]);
    let (_, mut sa) = new_session(&mut server, &a, ClientOptions::default());
    let q = sa.query().unwrap();
    let body = post(&mut server, &q, IP);
    let resp = sa.feed(&body).unwrap().clone();
    // identity B continues A's transaction
    let mut sb = Session::new(b, sa.url().clone(), ClientOptions::default(), None);
    sb.feed(&resp.raw).unwrap();
    let i = sb.ident().unwrap();
    let body = post(&mut server, &i, IP);
    let tif = sb.feed(&body).unwrap().tif;
    assert!(tif.bad_id_association());
}

#[test]
fn alt_id_yields_a_different_identity_on_the_same_site() {
    let identity = UnlockedIdentity::from_iuk(&[19u8; 32]);
    let url = SqrlUrl::parse("sqrl://example.com/cli.sqrl?nut=1").unwrap();
    let plain = Session::new(
        identity.clone(),
        url.clone(),
        ClientOptions::default(),
        None,
    );
    let alt = Session::new(identity, url, ClientOptions::default(), Some("work"));
    assert_ne!(plain.idk(), alt.idk());
}
