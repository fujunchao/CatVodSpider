package com.github.catvod.spider;

import android.content.Context;
import android.util.Base64;
import android.util.Log;

import com.github.catvod.crawler.Spider;
import com.github.catvod.net.Net;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ThreadLocalRandom;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 看看鸭（kankanya.me）Java 源 —— 由 D:/augment-projects/tvb/py/kky.py 逐段移植。
 *
 * 站点三层：
 *  1) 全站 WAF：页面可能返回「人机验证」，算法为 62 字符私有字母表 +3 位移、每字符前后插随机字符再 base64；
 *     POST /robot.php 带 value=encrypt(当前URL) & token=encrypt(页面 var token)。
 *  2) 播放页 var player_aaaa.url 是 kkyplayer 的 vid 令牌，POST /kkyplayer/api.php 拿回后解密成直链。
 *  3) api.php 有概率返回 urlmode=1 的诱饵，间隔 1.2s 重试最多 6 次。
 *
 * 与 py 版的差异：HTTP 走宿主注入的 Net（壳的 OkHttp 连接池），会话用 net.session() 保持 cookie。
 */
public class Kky extends Spider {

    private static final String TAG = "KKY";
    private static final String BASE = "https://www.kankanya.me";
    private static final String ALPHA = "PXhw7UT1B0a9kQDKZsjIASmOezxYG4CHo5Jyfg2b8FLpEvRr3WtVnlqMidu6cN";
    private static final String UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";
    private static final String[][] CATS = {{"dianying", "电影"}, {"juji", "剧集"}, {"zongyi", "综艺"}, {"dongman", "动漫"}};

    private static final Pattern RE_ITEM = Pattern.compile("<a href=\"(/detail/[^\"]+)\" title=\"([^\"]*)\" class=\"module-poster-item[^\"]*\">([\\s\\S]{0,600}?)</a>");
    private static final Pattern RE_PLAY_CFG = Pattern.compile("var player_aaaa=(\\{[\\s\\S]*?\\});?</script>");
    private static final Pattern RE_PLAY_LINK = Pattern.compile("<a\\s+class=\"module-play-list-link\"\\s+href=\"(/play/[^\"]+)\"[^>]*><span>([^<]*)</span>");
    private static final Pattern RE_TAG = Pattern.compile("<[^>]+>");
    private static final Pattern RE_NOTE = Pattern.compile("module-item-note\">([^<]*)<");
    private static final Pattern RE_PIC = Pattern.compile("data-original=\"([^\"]+)\"");
    private static final Pattern RE_VID = Pattern.compile("/detail/([^/]+?)\\.html");
    private static final Pattern RE_TOKEN = Pattern.compile("var token = encrypt\\(\"([^\"]*)\"\\)");
    private static final Pattern RE_YEAR = Pattern.compile("^\\d{4}$");

    private String host = BASE;
    private Net sess;
    private final Map<String, Object[]> cache = new HashMap<>();

    @Override
    public void init(Context context, String extend) {
        long t0 = System.currentTimeMillis();
        String ext = extend == null ? "" : extend.trim();
        if (ext.contains("http")) {
            try {
                String[] p = ext.split("://", 2);
                String hostPart = p[1].split("/", 2)[0];
                if (!hostPart.isEmpty()) host = p[0] + "://" + hostPart;
            } catch (Exception ignored) {
            }
        }
        sess = null;
        cache.clear();
        Log.i(TAG, "[KKY] init host=" + host + " " + (System.currentTimeMillis() - t0) + "ms");
    }

    @Override
    public boolean isVideoFormat(String url) {
        String u = url == null ? "" : url.toLowerCase();
        return u.contains(".m3u8") || u.contains(".mp4");
    }

    @Override
    public boolean manualVideoCheck() {
        return false;
    }

    @Override
    public void destroy() {
        cache.clear();
    }

    // ---------------- HTTP ----------------

    private Net session() {
        if (sess == null) sess = net == null ? new Net() : net.session();
        return sess;
    }

    private String raw(String method, String url, String body, String referer, Map<String, String> extra) {
        long t0 = System.currentTimeMillis();
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("User-Agent", UA);
        headers.put("Accept-Language", "zh-CN,zh;q=0.9");
        headers.put("Referer", referer == null || referer.isEmpty() ? host + "/" : referer);
        if (extra != null) headers.putAll(extra);
        String out = "";
        try {
            out = "POST".equals(method) ? session().post(url, body == null ? "" : body, headers) : session().get(url, headers);
        } catch (Exception e) {
            Log.w(TAG, "[KKY] request fail " + method + " " + cut(url) + ": " + e);
        }
        Log.i(TAG, "[KKY] http " + method + " " + (System.currentTimeMillis() - t0) + "ms len=" + (out == null ? 0 : out.length()) + " " + cut(url));
        return out == null ? "" : out;
    }

    private String httpGet(String url, String referer) {
        String text = "";
        for (int i = 0; i < 3; i++) {
            text = raw("GET", url, null, referer, null);
            if (text.isEmpty()) return "";
            if (text.contains("人机验证") && text.contains("/robot.php")) {
                if (passWaf(url, text)) continue;
                return "";
            }
            return text;
        }
        return "";
    }

    private boolean passWaf(String url, String text) {
        try {
            Matcher m = RE_TOKEN.matcher(text);
            if (!m.find()) return false;
            String body = "value=" + enc(url) + "&token=" + enc(m.group(1));
            Map<String, String> extra = new LinkedHashMap<>();
            extra.put("Content-Type", "application/x-www-form-urlencoded");
            raw("POST", host + "/robot.php", body, url, extra);
            Log.i(TAG, "[KKY] waf passed: " + cut(url));
            return true;
        } catch (Exception e) {
            Log.w(TAG, "[KKY] waf fail: " + e);
            return false;
        }
    }

    // ---------------- 加解密 ----------------

    private static String enc(String text) {
        StringBuilder sb = new StringBuilder(text.length() * 3);
        ThreadLocalRandom rnd = ThreadLocalRandom.current();
        for (char ch : text.toCharArray()) {
            int n = ALPHA.indexOf(ch);
            char code = n < 0 ? ch : ALPHA.charAt((n + 3) % 62);
            sb.append(ALPHA.charAt(rnd.nextInt(62))).append(code).append(ALPHA.charAt(rnd.nextInt(62)));
        }
        return Base64.encodeToString(sb.toString().getBytes(StandardCharsets.UTF_8), Base64.NO_WRAP);
    }

    private static String dec(String token) {
        try {
            byte[] raw = Base64.decode(token, Base64.DEFAULT);
            StringBuilder sb = new StringBuilder(raw.length / 3 + 1);
            for (int i = 1; i < raw.length; i += 3) {
                char ch = (char) (raw[i] & 0xff);
                int n = ALPHA.indexOf(ch);
                sb.append(n < 0 ? ch : ALPHA.charAt((n + 59) % 62));
            }
            return sb.toString();
        } catch (Exception e) {
            return "";
        }
    }

    // ---------------- 解析 ----------------

    private static String vid(String href) {
        Matcher m = RE_VID.matcher(href == null ? "" : href);
        return m.find() ? m.group(1) : (href == null ? "" : href);
    }

    private static List<JsonObject> items(String html) {
        List<JsonObject> out = new ArrayList<>();
        if (html == null) return out;
        Matcher m = RE_ITEM.matcher(html);
        while (m.find()) {
            String body = m.group(3);
            out.add(vod(vid(m.group(1)), m.group(2).trim(), first(RE_PIC, body), first(RE_NOTE, body)));
        }
        return out;
    }

    private static List<JsonObject> cards(String html) {
        List<JsonObject> out = new ArrayList<>();
        if (html == null) return out;
        String[] chunks = html.split("class=\"module-card-item module-item\"");
        for (int i = 1; i < chunks.length; i++) {
            String chunk = chunks[i];
            Matcher href = Pattern.compile("href=\"(/detail/[^\"]+)\"").matcher(chunk);
            if (!href.find()) continue;
            Matcher title = Pattern.compile("<strong>([^<]*)</strong>").matcher(chunk);
            if (!title.find()) title = Pattern.compile("module-card-item-title[\\s\\S]{0,80}?>([^<>]{1,60})<").matcher(chunk);
            if (!title.find()) continue;
            out.add(vod(vid(href.group(1)), title.group(1).trim(), first(RE_PIC, chunk), first(RE_NOTE, chunk)));
        }
        return out;
    }

    private static String first(Pattern p, String text) {
        Matcher m = p.matcher(text == null ? "" : text);
        return m.find() ? m.group(1).trim() : "";
    }

    private static JsonObject vod(String id, String name, String pic, String remarks) {
        JsonObject o = new JsonObject();
        o.addProperty("vod_id", id);
        o.addProperty("vod_name", name);
        o.addProperty("vod_pic", pic);
        o.addProperty("vod_remarks", remarks);
        return o;
    }

    // ---------------- 入口 ----------------

    @Override
    public String homeContent(boolean filter) {
        long t0 = System.currentTimeMillis();
        JsonArray classes = new JsonArray();
        for (String[] c : CATS) {
            JsonObject o = new JsonObject();
            o.addProperty("type_id", c[0]);
            o.addProperty("type_name", c[1]);
            classes.add(o);
        }
        List<JsonObject> videos = new ArrayList<>();
        try {
            List<JsonObject> all = items(httpGet(host + "/", null));
            if (all.isEmpty()) all = items(httpGet(host + "/show/dianying-----------.html", null));
            Map<String, Boolean> seen = new HashMap<>();
            for (JsonObject v : all) {
                String id = v.get("vod_id").getAsString();
                if (seen.containsKey(id)) continue;
                seen.put(id, true);
                videos.add(v);
                if (videos.size() >= 60) break;
            }
        } catch (Exception e) {
            Log.w(TAG, "[KKY] homeContent fail: " + e);
        }
        JsonObject out = new JsonObject();
        out.add("class", classes);
        out.add("filters", new JsonObject());
        out.add("list", toArray(videos));
        Log.i(TAG, "[KKY] homeContent " + (System.currentTimeMillis() - t0) + "ms videos=" + videos.size());
        return out.toString();
    }

    @Override
    public String categoryContent(String tid, String pg, boolean filter, HashMap<String, String> extend) {
        long t0 = System.currentTimeMillis();
        String cat = tid == null || tid.trim().isEmpty() ? "dianying" : tid.trim();
        int page = Math.max(1, num(pg, 1));
        List<JsonObject> videos = new ArrayList<>();
        try {
            String url = page <= 1 ? String.format("%s/show/%s-----------.html", host, cat) : String.format("%s/show/%s--------%d---.html", host, cat, page);
            videos = items(httpGet(url, null));
            if (videos.isEmpty() && page <= 1) videos = items(httpGet(String.format("%s/type/%s.html", host, cat), null));
        } catch (Exception e) {
            Log.w(TAG, "[KKY] categoryContent fail: " + e);
        }
        JsonObject out = new JsonObject();
        out.add("list", toArray(videos));
        out.addProperty("page", page);
        out.addProperty("pagecount", videos.size() >= 20 ? page + 1 : page);
        out.addProperty("limit", videos.size());
        out.addProperty("total", 999999);
        Log.i(TAG, "[KKY] categoryContent " + cat + "/" + page + " " + (System.currentTimeMillis() - t0) + "ms videos=" + videos.size());
        return out.toString();
    }

    @Override
    public String detailContent(List<String> ids) {
        long t0 = System.currentTimeMillis();
        JsonArray list = new JsonArray();
        try {
            String id = vid(String.valueOf(ids.get(0)));
            String html = httpGet(String.format("%s/detail/%s.html", host, id), null);
            if (html.isEmpty() || html.contains("Not Found") && html.indexOf("Not Found") < 2000) {
                return emptyList();
            }
            String name = regex(html, "<h1>([^<]+)</h1>");
            if (name.isEmpty()) {
                Log.w(TAG, "[KKY] detail no title: " + id);
                return emptyList();
            }
            List<String> tags = new ArrayList<>();
            Matcher tagMatcher = Pattern.compile("<div class=\"module-info-tag-link\"><a title=\"([^\"]*)\"").matcher(html);
            while (tagMatcher.find()) tags.add(tagMatcher.group(1));
            String year = !tags.isEmpty() && RE_YEAR.matcher(tags.get(0)).matches() ? tags.get(0) : "";
            String area = tags.size() > 1 && !RE_YEAR.matcher(tags.get(1)).matches() ? tags.get(1) : "";

            String content = RE_TAG.matcher(regex(html, "module-info-introduction-content\">([\\s\\S]*?)</div>")).replaceAll("").trim();
            if (content.length() > 1200) content = content.substring(0, 1200);

            JsonObject v = vod(id, name, regex(html, "class=\"module-info-poster\"[\\s\\S]{0,300}?data-original=\"([^\"]+)\""), "");
            v.addProperty("vod_year", year);
            v.addProperty("vod_area", area);
            v.addProperty("vod_remarks", regex(html, "集数：</span>\\s*<div class=\"module-info-item-content\">([^<]*)<"));
            v.addProperty("vod_actor", firstNonEmpty(people(html, "主演"), people(html, "演员")));
            v.addProperty("vod_director", people(html, "导演"));
            v.addProperty("vod_content", content);

            List<String> names = new ArrayList<>();
            Matcher nameMatcher = Pattern.compile("data-dropdown-value=\"([^\"]*)\"").matcher(html);
            while (nameMatcher.find()) names.add(nameMatcher.group(1));
            String[] chunks = html.split("<div class=\"module-play-list\">");
            List<String> froms = new ArrayList<>();
            List<String> urls = new ArrayList<>();
            for (int i = 1; i < chunks.length; i++) {
                Matcher pm = RE_PLAY_LINK.matcher(chunks[i]);
                List<String> plays = new ArrayList<>();
                while (pm.find()) {
                    String label = pm.group(2) == null ? "" : pm.group(2).trim();
                    if (label.isEmpty()) label = String.format("第%02d集", plays.size() + 1);
                    plays.add(label + "$" + pm.group(1));
                }
                if (plays.isEmpty()) continue;
                froms.add(i - 1 < names.size() && !names.get(i - 1).isEmpty() ? names.get(i - 1) : String.format("线路%d", froms.size() + 1));
                urls.add(String.join("#", plays));
            }
            v.addProperty("vod_play_from", String.join("$$$", froms));
            v.addProperty("vod_play_url", String.join("$$$", urls));
            list.add(v);
            Log.i(TAG, "[KKY] detailContent " + (System.currentTimeMillis() - t0) + "ms lines=" + froms.size());
        } catch (Exception e) {
            Log.w(TAG, "[KKY] detailContent fail: " + e);
            return emptyList();
        }
        JsonObject out = new JsonObject();
        out.add("list", list);
        return out.toString();
    }

    @Override
    public String searchContent(String key, boolean quick) {
        return searchContent(key, quick, "1");
    }

    @Override
    public String searchContent(String key, boolean quick, String pg) {
        long t0 = System.currentTimeMillis();
        String k = key == null ? "" : key.trim();
        List<JsonObject> videos = new ArrayList<>();
        if (!k.isEmpty()) {
            try {
                String url = String.format("%s/search/-------------.html?wd=%s", host, encode(k));
                String html = httpGet(url, null);
                videos = cards(html);
                if (videos.isEmpty()) videos = items(html);
                if (videos.isEmpty() && !quick) videos = localSearch(k);
            } catch (Exception e) {
                Log.w(TAG, "[KKY] searchContent fail: " + e);
            }
        }
        JsonObject out = new JsonObject();
        out.add("list", toArray(videos));
        out.addProperty("page", num(pg, 1));
        Log.i(TAG, "[KKY] searchContent " + k + " " + (System.currentTimeMillis() - t0) + "ms videos=" + videos.size());
        return out.toString();
    }

    private List<JsonObject> localSearch(String key) {
        List<JsonObject> out = new ArrayList<>();
        Map<String, Boolean> seen = new HashMap<>();
        try {
            for (int pg = 1; pg <= 3; pg++) {
                List<String> urls = new ArrayList<>();
                if (pg == 1) urls.add(host + "/");
                for (String[] c : CATS) urls.add(pg == 1 ? String.format("%s/show/%s-----------.html", host, c[0]) : String.format("%s/show/%s--------%d---.html", host, c[0], pg));
                for (String url : urls) {
                    for (JsonObject v : items(httpGet(url, null))) {
                        String id = v.get("vod_id").getAsString();
                        if (seen.containsKey(id)) continue;
                        seen.put(id, true);
                        String name = v.get("vod_name").getAsString();
                        if (name.contains(key) || key.contains(name)) out.add(v);
                    }
                }
                if (!out.isEmpty()) break;
            }
        } catch (Exception e) {
            Log.w(TAG, "[KKY] localSearch fail: " + e);
        }
        return out.size() > 30 ? out.subList(0, 30) : out;
    }

    @Override
    public String playerContent(String flag, String id, List<String> vipFlags) {
        long t0 = System.currentTimeMillis();
        Map<String, String> header = new LinkedHashMap<>();
        header.put("User-Agent", UA);
        String url = "";
        try {
            String raw = id == null ? "" : id.trim();
            String playPage = raw.startsWith("http") ? raw : raw.startsWith("/") ? host + raw : String.format("%s/play/%s.html", host, raw);
            url = playUrl(playPage);
        } catch (Exception e) {
            Log.w(TAG, "[KKY] playerContent fail: " + e);
        }
        JsonObject out = new JsonObject();
        out.addProperty("parse", 0);
        out.addProperty("url", url);
        JsonObject h = new JsonObject();
        for (Map.Entry<String, String> e : header.entrySet()) h.addProperty(e.getKey(), e.getValue());
        out.add("header", h);
        Log.i(TAG, "[KKY] playerContent " + (System.currentTimeMillis() - t0) + "ms url=" + (url.isEmpty() ? "EMPTY" : cut(url)));
        return out.toString();
    }

    private String playUrl(String playPage) {
        String html = httpGet(playPage, host + "/");
        Matcher m = RE_PLAY_CFG.matcher(html);
        if (!m.find()) {
            Log.w(TAG, "[KKY] no player_aaaa: " + cut(playPage));
            return "";
        }
        String token = "";
        try {
            token = JsonParser.parseString(m.group(1)).getAsJsonObject().get("url").getAsString();
        } catch (Exception e) {
            Log.w(TAG, "[KKY] player_aaaa parse fail: " + e);
            return "";
        }
        if (token.isEmpty()) return "";
        Object[] hit = cache.get(token);
        if (hit != null && System.currentTimeMillis() / 1000 - (Long) hit[1] < 1800) return (String) hit[0];

        String api = host + "/kkyplayer/api.php";
        for (int i = 1; i <= 6; i++) {
            Map<String, String> extra = new LinkedHashMap<>();
            extra.put("Origin", host);
            extra.put("Content-Type", "application/x-www-form-urlencoded");
            String txt = raw("POST", api, "vid=" + encode(token), playPage, extra);
            try {
                JsonObject j = JsonParser.parseString(txt).getAsJsonObject();
                JsonObject data = j.has("data") && j.get("data").isJsonObject() ? j.getAsJsonObject("data") : new JsonObject();
                String url = dec(data.has("url") ? data.get("url").getAsString() : "");
                if (url.startsWith("http")) {
                    cache.put(token, new Object[]{url, System.currentTimeMillis() / 1000});
                    Log.i(TAG, "[KKY] play hit #" + i + " urlmode=" + (data.has("urlmode") ? data.get("urlmode").toString() : "-") + " " + cut(url));
                    return url;
                }
            } catch (Exception ignored) {
            }
            try {
                Thread.sleep(1200);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
        Log.w(TAG, "[KKY] play failed after 6 tries: " + cut(playPage));
        return "";
    }

    // ---------------- 工具 ----------------

    private static JsonArray toArray(List<JsonObject> list) {
        JsonArray arr = new JsonArray();
        for (JsonObject o : list) arr.add(o);
        return arr;
    }

    private static String emptyList() {
        JsonObject out = new JsonObject();
        out.add("list", new JsonArray());
        return out.toString();
    }

    private static String people(String html, String label) {
        Matcher m = Pattern.compile(label + "：</span>[\\s\\S]{0,120}?<div class=\"module-info-item-content\">([\\s\\S]*?)</div>").matcher(html);
        if (!m.find()) return "";
        String text = RE_TAG.matcher(m.group(1)).replaceAll(" ").replace("/", ",");
        List<String> names = new ArrayList<>();
        for (String n : text.split(",")) if (!n.trim().isEmpty()) names.add(n.trim());
        String joined = String.join(",", names);
        return joined.length() > 300 ? joined.substring(0, 300) : joined;
    }

    private static String regex(String text, String pattern) {
        Matcher m = Pattern.compile(pattern).matcher(text == null ? "" : text);
        return m.find() ? m.group(1).trim() : "";
    }

    private static String firstNonEmpty(String a, String b) {
        return a == null || a.isEmpty() ? (b == null ? "" : b) : a;
    }

    private static int num(String v, int d) {
        try {
            return Integer.parseInt(v);
        } catch (Exception e) {
            return d;
        }
    }

    private static String encode(String s) {
        try {
            return URLEncoder.encode(s, "UTF-8").replace("+", "%20");
        } catch (Exception e) {
            return s;
        }
    }

    private static String cut(String s) {
        return s == null ? "" : s.length() > 110 ? s.substring(0, 110) : s;
    }
}
