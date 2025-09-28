const API_KEY = "YOUR_API_KEY"; // Replace with your real Google Safe Browsing API key
const API_URL = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${API_KEY}`;
const CACHE_TTL = 60 * 60 * 1000; // 1 hour cache (in ms)

async function getCurrentDomainAndURL() {
  return new Promise(resolve => {
    chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
      const url = new URL(tabs[0].url);
      resolve({ domain: url.hostname, fullUrl: url.href });
    });
  });
}

async function updateLists() {
  let { whitelist = [], blacklist = [] } = await chrome.storage.local.get(["whitelist", "blacklist"]);

  document.getElementById("whitelist").innerHTML = whitelist.map(d => `<li>${d}</li>`).join("");
  document.getElementById("blacklist").innerHTML = blacklist.map(d => `<li>${d}</li>`).join("");
}

async function checkCache(url) {
  let { cache = {} } = await chrome.storage.local.get("cache");

  if (cache[url]) {
    const { verdict, color, timestamp } = cache[url];
    if (Date.now() - timestamp < CACHE_TTL) {
      console.log("Cache hit for:", url);
      return { verdict, color, cached: true };
    } else {
      console.log("Cache expired for:", url);
    }
  }
  return null;
}

async function saveToCache(url, verdict, color) {
  let { cache = {} } = await chrome.storage.local.get("cache");
  cache[url] = { verdict, color, timestamp: Date.now() };
  await chrome.storage.local.set({ cache });
}

async function checkSafeBrowsing(url) {
  // First check cache
  const cached = await checkCache(url);
  if (cached) return cached;

  // Otherwise → API request
  let body = {
    client: { clientId: "phishguard", clientVersion: "1.3" },
    threatInfo: {
      threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "POTENTIALLY_HARMFUL_APPLICATION"],
      platformTypes: ["ANY_PLATFORM"],
      threatEntryTypes: ["URL"],
      threatEntries: [{ url }]
    }
  };

  try {
    let response = await fetch(API_URL, {
      method: "POST",
      body: JSON.stringify(body)
    });

    let data = await response.json();

    let verdict, color;
    if (data.matches) {
      verdict = "Malicious 🚨";
      color = "red";
    } else {
      verdict = "Safe ✅";
      color = "green";
    }

    await saveToCache(url, verdict, color);
    return { verdict, color, cached: false };
  } catch (error) {
    console.error("Scan failed:", error);
    return { verdict: "Error ⚠️", color: "orange", cached: false };
  }
}

async function init() {
  const { domain, fullUrl } = await getCurrentDomainAndURL();
  document.getElementById("status").innerText = `Current site: ${domain}`;

  // Check whitelist/blacklist
  let { whitelist = [], blacklist = [] } = await chrome.storage.local.get(["whitelist", "blacklist"]);

  if (whitelist.includes(domain)) {
    document.getElementById("result").innerText = "Whitelisted ✅";
    document.getElementById("result").style.color = "blue";
    return;
  }

  if (blacklist.includes(domain)) {
    document.getElementById("result").innerText = "Blacklisted 🚨";
    document.getElementById("result").style.color = "red";
    return;
  }

  // Otherwise → Scan with Safe Browsing
  const scan = await checkSafeBrowsing(fullUrl);
  document.getElementById("result").innerText = scan.verdict + (scan.cached ? " (cached)" : "");
  document.getElementById("result").style.color = scan.color;

  // Button actions
  document.getElementById("whitelistBtn").addEventListener("click", async () => {
    if (!whitelist.includes(domain)) whitelist.push(domain);
    await chrome.storage.local.set({ whitelist });
    updateLists();
  });

  document.getElementById("blacklistBtn").addEventListener("click", async () => {
    if (!blacklist.includes(domain)) blacklist.push(domain);
    await chrome.storage.local.set({ blacklist });
    updateLists();
  });

  updateLists();
}

init();
