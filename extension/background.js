// Background service worker (Chrome) / event page (Firefox).
//
// Responsibilities:
//  * Register declarativeNetRequest rules that turn the extension into a "local SQRL
//    client" for websites: requests to http://localhost:25519/ (the port every native SQRL
//    client listens on for Client Provided Session) are redirected into the extension.
//    - the presence probe  http://localhost:25519/<random>.gif  → img/cps.gif
//    - the login navigation http://localhost:25519/<base64url sqrl url> → auth.html?cps=…
//  * Open the authentication window when a content script reports a clicked sqrl:// link.
//  * Keep the QuickPass (held in chrome.storage.session, never on disk) and clear it on
//    idle / lock / timeout.
//  * Remember which tabs currently show SQRL links so the toolbar popup can offer them.

const api = globalThis.browser ?? globalThis.chrome;

const CPS_PORT = 25519;
const RULE_PROBE = 1;
const RULE_LOGIN = 2;
const QUICKPASS_ALARM = 'sqrl-quickpass-expire';

async function installRules() {
  const base = api.runtime.getURL('');
  const rules = [
    {
      id: RULE_PROBE,
      priority: 2,
      action: { type: 'redirect', redirect: { url: base + 'img/cps.gif' } },
      condition: {
        regexFilter: `^http://localhost:${CPS_PORT}/[^?#]*\\.gif(\\?.*)?$`,
        resourceTypes: ['image', 'xmlhttprequest', 'other']
      }
    },
    {
      id: RULE_LOGIN,
      priority: 1,
      action: {
        type: 'redirect',
        redirect: { regexSubstitution: base + 'auth.html?cps=\\1' }
      },
      condition: {
        regexFilter: `^http://localhost:${CPS_PORT}/([A-Za-z0-9_=-]+)`,
        resourceTypes: ['main_frame']
      }
    }
  ];
  try {
    await api.declarativeNetRequest.updateDynamicRules({
      removeRuleIds: rules.map((r) => r.id),
      addRules: rules
    });
  } catch (e) {
    console.error('SQRL: could not install CPS rules', e);
  }
}

api.runtime.onInstalled.addListener(() => {
  installRules();
});
api.runtime.onStartup.addListener(() => {
  installRules();
});
// Service workers may be restarted without onInstalled/onStartup firing; rules are
// persistent, but re-asserting them is cheap and keeps the extension URL in sync.
installRules();

// ---------------------------------------------------------------------------------------
// QuickPass lifecycle
// ---------------------------------------------------------------------------------------

async function clearQuickPass(reason) {
  try {
    await api.storage.session.remove('quickpass');
    await api.alarms.clear(QUICKPASS_ALARM);
    if (reason) console.info('SQRL: QuickPass cleared (' + reason + ')');
  } catch (e) {
    /* storage.session unavailable: nothing to clear */
  }
}

async function armQuickPassTimeout(minutes) {
  await api.alarms.clear(QUICKPASS_ALARM);
  if (minutes > 0) {
    api.alarms.create(QUICKPASS_ALARM, { delayInMinutes: minutes });
  }
}

api.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === QUICKPASS_ALARM) clearQuickPass('idle timeout');
});

if (api.idle && api.idle.onStateChanged) {
  api.idle.onStateChanged.addListener(async (state) => {
    if (state === 'locked') {
      clearQuickPass('system locked');
    } else if (state === 'idle') {
      const { quickpass } = await api.storage.session.get('quickpass').catch(() => ({}));
      if (quickpass && quickpass.clearOnIdle) clearQuickPass('system idle');
    }
  });
}

// ---------------------------------------------------------------------------------------
// Tabs that currently show SQRL links (reported by content.js)
// ---------------------------------------------------------------------------------------

const tabLinks = new Map();

api.tabs.onRemoved.addListener((tabId) => tabLinks.delete(tabId));
api.tabs.onUpdated.addListener((tabId, info) => {
  if (info.status === 'loading') tabLinks.delete(tabId);
});

// ---------------------------------------------------------------------------------------
// Authentication window
// ---------------------------------------------------------------------------------------

async function openAuthWindow(sqrlUrl, tabId, windowId) {
  const params = new URLSearchParams({ u: sqrlUrl });
  if (tabId != null) params.set('tab', String(tabId));
  const url = api.runtime.getURL('auth.html?' + params.toString());
  const popup = await api.windows.create({
    url,
    type: 'popup',
    width: 460,
    height: 640,
    focused: true
  });
  return popup.id;
}

api.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  (async () => {
    switch (msg && msg.type) {
      case 'sqrl-link-clicked': {
        const tabId = sender.tab ? sender.tab.id : null;
        const windowId = sender.tab ? sender.tab.windowId : null;
        await openAuthWindow(msg.url, tabId, windowId);
        return { ok: true };
      }
      case 'sqrl-links-found': {
        if (sender.tab && sender.frameId === 0) {
          tabLinks.set(sender.tab.id, msg.urls.slice(0, 10));
        } else if (sender.tab && !tabLinks.has(sender.tab.id)) {
          tabLinks.set(sender.tab.id, msg.urls.slice(0, 10));
        }
        return { ok: true };
      }
      case 'get-tab-links': {
        return { urls: tabLinks.get(msg.tabId) || [] };
      }
      case 'open-auth': {
        await openAuthWindow(msg.url, msg.tabId ?? null, null);
        return { ok: true };
      }
      case 'quickpass-set': {
        await api.storage.session.set({ quickpass: msg.quickpass });
        await armQuickPassTimeout(msg.quickpass.idleTimeoutMinutes);
        return { ok: true };
      }
      case 'quickpass-touch': {
        await armQuickPassTimeout(msg.idleTimeoutMinutes);
        return { ok: true };
      }
      case 'quickpass-clear': {
        await clearQuickPass(msg.reason || 'requested');
        return { ok: true };
      }
      case 'navigate-tab': {
        if (msg.tabId != null) {
          try {
            await api.tabs.update(msg.tabId, { url: msg.url, active: true });
          } catch (e) {
            await api.tabs.create({ url: msg.url });
          }
        } else {
          await api.tabs.create({ url: msg.url });
        }
        return { ok: true };
      }
      case 'reinstall-rules': {
        await installRules();
        return { ok: true };
      }
      default:
        return { error: 'unknown message' };
    }
  })().then(sendResponse, (e) => sendResponse({ error: String(e) }));
  return true;
});
