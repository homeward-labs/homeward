/**
 * 家卫知识库内容源 · Cloudflare Worker
 *
 * 职责：把 KV 命名空间（绑定名 KB）里的静态文件按路径返回给客户端 updater。
 * 客户端只拉取固定几个文件：VERSION / domains.csv / behaviors.json /
 * oui_prefixes.csv / CHECKSUM / SIGNATURE（见 src/knowledge_base/constants.py）。
 *
 * 由 scripts/publish_kb_source.py 把 bundle 推到同一个 KV 命名空间即可。
 * 不需要任何后端、不做账号体系、不记录域名级查询（隐私红线）。
 *
 * 部署：
 *   wrangler deploy            # 用同目录 wrangler.toml 里的 account_id / kv 绑定
 * 本地联调：
 *   wrangler dev
 */
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    let key = url.pathname.replace(/^\/+/, ""); // 去前导斜杠
    if (key === "" || key === "index.html" || key === "index.txt") {
      // 根路径默认返回 VERSION，方便一眼确认生效版本
      key = "VERSION";
    }

    const value = await env.KB.get(key);
    if (value === null) {
      return new Response("Not Found: " + key, { status: 404 });
    }

    const ct = key.endsWith(".json")
      ? "application/json; charset=utf-8"
      : key.endsWith(".csv")
      ? "text/csv; charset=utf-8"
      : "text/plain; charset=utf-8";

    return new Response(value, {
      headers: {
        "content-type": ct,
        "cache-control": "public, max-age=3600",
        // 跨域：客户端用 fetch 拉取，本地/内网镜像同源无需，但公网源建议放开
        "access-control-allow-origin": "*",
      },
    });
  },
};
