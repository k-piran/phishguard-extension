const API_KEY = "YOUR_API_KEY"; // Replace with real Google Safe Browsing API key
const API_URL = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${API_KEY}`;

chrome.webRequest.onBeforeRequest.addListener(
  async function (details) {
    if (details.type === "main_frame") {
      let urlToCheck = details.url;
      const domain = new URL(urlToCheck).hostname;

      // Load whitelist & blacklist
      let { whitelist = [], blacklist = [] } = await chrome.storage.local.get(["whitelist", "blacklist"]);

      // If in whitelist → allow
      if (whitelist.includes(domain)) {
        console.log("Whitelisted:", domain);
        return;
      }

      // If in blacklist → block immediately
      if (blacklist.includes(domain)) {
        console.warn("Blocked (blacklist):", domain);
        return { redirectUrl: chrome.runtime.getURL("block.html") };
      }

      // Google Safe Browsing check
      let body = {
        client: { clientId: "phishguard", clientVersion: "1.1" },
        threatInfo: {
          threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "POTENTIALLY_HARMFUL_APPLICATION"],
          platformTypes: ["ANY_PLATFORM"],
          threatEntryTypes: ["URL"],
          threatEntries: [{ url: urlToCheck }]
        }
      };

      try {
        let response = await fetch(API_URL, { method: "POST", body: JSON.stringify(body) });
        let data = await response.json();

        if (data.matches) {
          console.warn("Blocked (Google Safe Browsing):", domain);
          return { redirectUrl: chrome.runtime.getURL("block.html") };
        }
      } catch (error) {
        console.error("Safe Browsing check failed:", error);
      }
    }
  },
  { urls: ["<all_urls>"] },
  ["blocking"]
);
