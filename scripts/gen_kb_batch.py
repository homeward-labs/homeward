#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""家卫知识库扩库（2026-10 批次）生成器。

产出 scripts/kb_new_2026_10.csv，字段同 domains.csv：
  domain,organization,category,confidence,description,action,side_effects

数据原则：只收录真实存在的域名（厂商根域 + 高置信通用子域），
不杜撰怪异子域。描述/副作用由脚本按 (category, action) 自动映射，
保证与 expand_homeward_kb.py 的 S_* 文案一致。

用法：
  python scripts/gen_kb_batch.py            # 写 CSV 并校验
  python scripts/gen_kb_batch.py --check    # 仅校验不写
"""
import csv
import re
import sys
from pathlib import Path

OUT = Path(__file__).resolve().parent / "kb_new_2026_10.csv"

# RAW 行格式： domain|org|cat|conf|action
# 多条以空行分组仅为了可读性，解析时忽略空行与注释(#)。
RAW = """
# ===== 智能家居 / IoT 设备云（核心通道 allow） =====
yeelight.com|Yeelight 易来|iot_core|high|allow
yeelight.net|Yeelight 易来|iot_core|high|allow
broadlink.com|BroadLink 博联|iot_core|high|allow
itead.cc|Sonoff / itead|iot_core|high|allow
sonoff.tech|Sonoff|iot_core|high|allow
sonoff.com|Sonoff|iot_core|high|allow
wyze.com|Wyze|iot_core|high|allow
switchbot.com|SwitchBot 唯创|iot_core|high|allow
govee.com|Govee|iot_core|high|allow
meross.com|Meross|iot_core|high|allow
tplinkcloud.com|TP-Link|iot_core|high|allow
kasa.com|TP-Link Kasa|iot_core|high|allow
tapo.com|TP-Link Tapo|iot_core|high|allow
arlo.com|Netgear Arlo|iot_core|high|allow
belkin.com|Belkin Wemo|iot_core|high|allow
ecovacs.com|科沃斯|iot_core|high|allow
narwal.com|云鲸|iot_core|high|allow
irobot.com|iRobot|iot_core|high|allow
shelly.cloud|Shelly|iot_core|medium|allow
shelly.com|Shelly|iot_core|medium|allow
athom.tech|Athom|iot_core|medium|allow
tasmota.com|Tasmota|iot_core|low|allow
home-assistant.io|Home Assistant|iot_core|medium|allow
hubitat.com|Hubitat|iot_core|medium|allow
smartthings.com|Samsung SmartThings|iot_core|high|allow
ezviz.com|萤石 EZViz|iot_core|high|allow
reolink.com|Reolink|iot_core|high|allow
dahuasecurity.com|大华|iot_core|high|allow
dahua.com|大华|iot_core|high|allow
hik-connect.com|海康威视|iot_core|high|allow
hikvision.com|海康威视|iot_core|high|allow
anker.com|Anker|iot_core|medium|allow

# ===== 家电厂商（核心通道 allow） =====
midea.com|美的|iot_core|high|allow
midea.net|美的|iot_core|high|allow
haier.com|海尔|iot_core|high|allow
casarte.com|卡萨帝|iot_core|medium|allow
gree.com|格力|iot_core|high|allow
hisense.com|海信|iot_core|high|allow
tcl.com|TCL|iot_core|high|allow
changhong.com|长虹|iot_core|high|allow
skyworth.com|创维|iot_core|high|allow
coocaa.com|酷开|iot_core|medium|allow
konka.com|康佳|iot_core|high|allow
panasonic.com|松下|iot_core|high|allow
sony.com|索尼|iot_core|high|allow
lg.com|LG|iot_core|high|allow
dyson.com|戴森|iot_core|high|allow
philips.com|飞利浦|iot_core|high|allow
meethue.com|Philips Hue|iot_core|high|allow
tineco.com|添可 Tineco|iot_core|medium|allow
fotile.com|方太|iot_core|high|allow
robam.com|老板|iot_core|high|allow
joyoung.com|九阳|iot_core|high|allow
supor.com|苏泊尔|iot_core|high|allow
bear.com.cn|小熊|iot_core|medium|allow
buydeem.com|北鼎|iot_core|medium|allow

# ===== 手机 / 系统厂商（核心通道 allow） =====
honor.com|荣耀|iot_core|high|allow
realme.com|realme|iot_core|high|allow
oneplus.com|一加|iot_core|high|allow
meizu.com|魅族|iot_core|high|allow
smartisan.com|坚果|iot_core|medium|allow
zte.com|中兴|iot_core|high|allow
lenovo.com|联想|iot_core|high|allow
lenovocn.com|联想|iot_core|medium|allow
motorola.com|摩托罗拉|iot_core|high|allow
hmd.com|诺基亚 HMD|iot_core|medium|allow
asus.com|华硕|iot_core|high|allow
miwifi.com|小米路由|iot_core|medium|allow
redmi.com|红米|iot_core|high|allow

# ===== 电视 / OTT / 视频（allow 或 block_soft） =====
iqiyi.com|爱奇艺|ott|high|allow
youku.com|优酷|ott|high|allow
mgtv.com|芒果 TV|ott|high|allow
bilibili.com|哔哩哔哩|ott|high|allow
douyin.com|抖音|ott|high|allow
kuaishou.com|快手|ott|high|allow
xigua.com|西瓜视频|ott|medium|allow
ximalaya.com|喜马拉雅|ott|high|allow
music.163.com|网易云音乐|ott|high|allow
y.qq.com|QQ 音乐|ott|high|allow
kugou.com|酷狗|ott|medium|allow
kuwo.cn|酷我|ott|low|allow
migu.cn|咪咕|ott|medium|allow
letv.com|乐视|ott|low|allow
pptv.com|PPTV|ott|low|allow

# ===== 广告 / 追踪 / 分析 SDK（block） =====
umeng.com|友盟 Umeng|analytics|high|block_soft
umeng.cn|友盟 Umeng|analytics|high|block_soft
mobclick.com|友盟 SDK|analytics|high|block_soft
talkingdata.com|TalkingData|analytics|high|block_soft
mob.com|Mobvista|advertising_sdk|medium|block_soft
mobvista.com|Mobvista|advertising_sdk|medium|block_soft
mintegral.com|Mintegral|advertising_sdk|medium|block_soft
oceanengine.com|巨量引擎|advertising|high|block_soft
gdt.qq.com|腾讯广告|advertising|high|block_soft
pangle.cn|穿山甲 Pangle|advertising_sdk|medium|block_soft
pangle.com|Pangle|advertising_sdk|medium|block_soft
getui.com|个推|developer_service|medium|block_soft
jiguang.cn|极光推送|developer_service|medium|block_soft
jpush.cn|极光推送|developer_service|medium|block_soft
dataeye.com|DataEye|analytics|medium|block_soft
reyun.com|热云|analytics|medium|block_soft
sentry.io|Sentry|developer_service|medium|block_soft
bugly.qq.com|腾讯 Bugly|developer_service|medium|block_soft
count.ly|Countly|analytics|medium|block_soft
heap.io|Heap|analytics|low|block_soft
mparticle.com|mParticle|analytics|low|block_soft
tealium.com|Tealium|analytics|low|block_soft
kochava.com|Kochava|advertising_sdk|low|block_soft
singular.net|Singular|advertising_sdk|low|block_soft
chartboost.com|Chartboost|advertising|low|block_soft
unity3d.com|Unity|advertising|medium|block_soft
unityads.unity3d.com|Unity Ads|advertising|medium|block_soft
ironsource.com|ironSource|advertising|low|block_soft
vungle.com|Vungle|advertising|low|block_soft
adcolony.com|AdColony|advertising|low|block_soft
applovin.com|AppLovin|advertising|low|block_soft
tapjoy.com|Tapjoy|advertising|low|block_soft
inmobi.com|InMobi|advertising|low|block_soft
mopub.com|MoPub|advertising|low|block_soft
pubmatic.com|PubMatic|advertising|low|block_soft
criteo.com|Criteo|advertising|medium|block_soft
thetradedesk.com|The Trade Desk|advertising|low|block_soft
doubleverify.com|DoubleVerify|advertising|low|block_soft
optimizely.com|Optimizely|analytics|low|block_soft
hotjar.com|Hotjar|analytics|low|block_soft
fullstory.com|FullStory|analytics|low|block_soft
logrocket.com|LogRocket|analytics|low|block_soft
clarity.ms|微软 Clarity|analytics|low|block_soft
yandex.ru|Yandex|analytics|low|block_soft
yandex.net|Yandex|analytics|low|block_soft
cnzz.com|CNZZ 统计|analytics|low|block_soft
51.la|51LA 统计|analytics|low|block_soft
sensorsdata.cn|神策数据|analytics|medium|block_soft
growingio.com|GrowingIO|analytics|medium|block_soft
zhugeio.com|诸葛 io|analytics|low|block_soft
analysys.cn|易观|analytics|low|block_soft
miaozhen.com|秒针|analytics|low|block_soft
nielsen.com|Nielsen|analytics|low|block_soft
comscore.com|Comscore|analytics|low|block_soft
similarweb.com|SimilarWeb|analytics|low|block_soft
segment.com|Segment|analytics|low|block_soft
mixpanel.com|Mixpanel|analytics|low|block_soft
amplitude.com|Amplitude|analytics|low|block_soft
mta.qq.com|腾讯移动分析|analytics|low|block_soft
hm.baidu.com|百度统计|analytics|low|block_soft
rubiconproject.com|Rubicon|advertising|low|block_soft
pubnative.com|PubNative|advertising|low|block_soft

# ===== 社交 / 通讯（allow 或 block_soft） =====
weixin.qq.com|微信|messaging|high|allow
wechat.com|微信|messaging|high|allow
weibo.com|微博|social|high|allow
dingtalk.com|钉钉|messaging|high|allow
feishu.cn|飞书|messaging|high|allow
larksuite.com|飞书|messaging|high|allow
work.weixin.qq.com|企业微信|messaging|high|allow
zhihu.com|知乎|social|medium|allow
douban.com|豆瓣|social|low|allow
xiaohongshu.com|小红书|social|medium|allow
tieba.baidu.com|百度贴吧|social|low|allow
momo.com|陌陌|social|low|allow
whatsapp.net|WhatsApp|messaging|medium|allow
line.me|LINE|messaging|medium|allow
x.com|X / Twitter|social|medium|allow
twitter.com|X / Twitter|social|medium|allow
instagram.com|Instagram|social|medium|allow
linkedin.com|LinkedIn|social|low|allow
pinterest.com|Pinterest|social|low|allow
reddit.com|Reddit|social|low|allow
tiktok.com|TikTok|social|medium|allow
snapchat.com|Snapchat|social|low|allow
tumblr.com|Tumblr|social|low|allow
medium.com|Medium|social|low|allow
quora.com|Quora|social|low|allow
vk.com|VK|social|low|allow
ok.ru|Odnoklassniki|social|low|allow

# ===== 电商 / 支付 / 生活（allow） =====
taobao.com|淘宝|shopping|high|allow
tmall.com|天猫|shopping|high|allow
jd.com|京东|shopping|high|allow
pinduoduo.com|拼多多|shopping|high|allow
yangkeduo.com|拼多多|shopping|high|allow
suning.com|苏宁|shopping|medium|allow
vip.com|唯品会|shopping|medium|allow
alipay.com|支付宝|finance|high|allow
alipayobjects.com|支付宝|finance|high|allow
unionpay.com|银联|finance|high|allow
meituan.com|美团|shopping|high|allow
dianping.com|大众点评|shopping|medium|allow
ele.me|饿了么|shopping|high|allow
didi.com|滴滴|travel|high|allow
didiglobal.com|滴滴|travel|high|allow
trip.com|携程|travel|high|allow
ctrip.com|携程|travel|high|allow
qunar.com|去哪儿|travel|high|allow
fliggy.com|飞猪|travel|medium|allow
ke.com|贝壳找房|shopping|medium|allow
lianjia.com|链家|shopping|medium|allow
58.com|58 同城|shopping|low|allow
ganji.com|赶集|shopping|low|allow
koubei.com|口碑|shopping|low|allow
yonghui.com|永辉|shopping|low|allow

# ===== 汽车 / 车机 / 地图（allow） =====
tesla.com|特斯拉|iot_core|high|allow
teslamotors.com|特斯拉|iot_core|high|allow
byd.com|比亚迪|iot_core|high|allow
nio.io|蔚来|iot_core|high|allow
nio.com|蔚来|iot_core|high|allow
xpeng.com|小鹏|iot_core|high|allow
lixiang.com|理想|iot_core|high|allow
amap.com|高德|map|high|allow
map.baidu.com|百度地图|map|high|allow
map.qq.com|腾讯地图|map|high|allow
navinfo.com|四维图新|map|medium|allow
autonavi.com|高德 AutoNavi|map|medium|allow
here.com|HERE|map|medium|allow
tomtom.com|TomTom|map|low|allow
mapbox.com|Mapbox|map|low|allow
careland.com|凯立德|map|low|allow

# ===== 穿戴 / 健康（allow） =====
fitbit.com|Fitbit|iot_core|high|allow
garmin.com|Garmin|iot_core|high|allow
keep.com|Keep|iot_core|medium|allow
amazfit.com|华米 Amazfit|iot_core|high|allow
huami.com|华米|iot_core|high|allow
zepp.com|Zepp|iot_core|medium|allow
whoop.com|WHOOP|iot_core|low|allow
oura.com|Oura|iot_core|low|allow
withings.com|Withings|iot_core|medium|allow
polar.com|Polar|iot_core|low|allow
suunto.com|Suunto|iot_core|low|allow

# ===== 运营商 / 区域（allow） =====
10086.cn|中国移动|iot_core|high|allow
cmcc.com|中国移动|iot_core|high|allow
189.cn|中国电信|iot_core|high|allow
chinatelecom.com|中国电信|iot_core|high|allow
10010.com|中国联通|iot_core|high|allow
chinaunicom.com|中国联通|iot_core|high|allow
ecloud.10086.cn|移动云|cloud|medium|allow

# ===== 路由 / 安防 / 网络设备（allow 或 block_soft） =====
netgear.com|网件|iot_core|medium|allow
tp-link.com|TP-Link|iot_core|high|allow
dlink.com|D-Link|iot_core|medium|allow
linksys.com|Linksys|iot_core|low|allow
ikuai8.com|爱快|iot_core|medium|allow
h3c.com|新华三|iot_core|medium|allow
ruijie.com|锐捷|iot_core|medium|allow
mikrotik.com|MikroTik|iot_core|low|allow
ubnt.com|Ubiquiti|iot_core|low|allow
ui.com|Ubiquiti|iot_core|low|allow
meraki.cisco.com|Cisco Meraki|iot_core|low|allow
cisco.com|思科|iot_core|medium|allow

# ===== 云 / CDN / 基础设施（allow） =====
huaweicloud.com|华为云|cloud|high|allow
qingcloud.com|青云|cloud|medium|allow
ucloud.cn|UCloud|cloud|medium|allow
jdcloud.com|京东云|cloud|medium|allow
ksyun.com|金山云|cloud|medium|allow
chinanetcenter.com|网宿|cdn|medium|allow
baishancloud.com|白山|cdn|low|allow
qiniu.com|七牛|cloud_storage|medium|allow
upyun.com|又拍|cloud_storage|low|allow
azureedge.net|Azure CDN|cdn|high|allow
azure.com|Azure|cloud|high|allow
fastly.net|Fastly|cdn|medium|allow
akamai.net|Akamai|cdn|high|allow
akamai.com|Akamai|cdn|high|allow
linode.com|Linode|cloud|low|allow
digitalocean.com|DigitalOcean|cloud|low|allow
vultr.com|Vultr|cloud|low|allow
heroku.com|Heroku|cloud|low|allow
netlify.com|Netlify|cloud|low|allow
vercel.com|Vercel|cloud|low|allow
render.com|Render|cloud|low|allow
oracle.com|Oracle Cloud|cloud|medium|allow
ibm.com|IBM Cloud|cloud|low|allow
jsdelivr.net|jsDelivr|cdn|medium|allow
unpkg.com|unpkg|cdn|low|allow
gstatic.com|Google Static|cdn|high|allow

# ===== 门户 / 新闻 / 搜索（allow 或 block_soft） =====
sohu.com|搜狐|news|low|allow
sina.com.cn|新浪|news|medium|allow
163.com|网易|news|medium|allow
126.com|网易|email|medium|allow
yeah.net|网易|email|low|allow
people.com.cn|人民网|news|low|allow
xinhuanet.com|新华网|news|low|allow
cctv.com|央视|news|low|allow
china.com|中华网|news|low|allow
so.com|360 搜索|search|low|allow
sogou.com|搜狗|search|low|allow
bing.com|微软 Bing|search|medium|allow

# ===== 游戏（allow 或 block_soft） =====
mihoyo.com|米哈游|gaming|medium|allow
steamcommunity.com|Valve Steam|gaming|medium|allow
steampowered.com|Valve Steam|gaming|medium|allow
epicgames.com|Epic|gaming|low|allow
blizzard.com|暴雪|gaming|low|allow
riotgames.com|Riot|gaming|low|allow
ea.com|EA|gaming|low|allow
ubisoft.com|Ubisoft|gaming|low|allow
xbox.com|微软 Xbox|gaming|medium|allow
nintendo.com|任天堂|gaming|low|allow

# ===== AI 服务（allow 或 block_soft） =====
openai.com|OpenAI|ai_service|medium|allow
anthropic.com|Anthropic|ai_service|low|allow
claude.ai|Anthropic|ai_service|low|allow
chat.openai.com|OpenAI ChatGPT|ai_service|medium|allow
hunyuan.tencent.com|腾讯混元|ai_service|medium|allow
qianwen.aliyun.com|阿里通义|ai_service|medium|allow
ernie.baidu.com|百度文心|ai_service|medium|allow
zhipuai.cn|智谱 AI|ai_service|low|allow
moonshot.cn|月之暗面 Kimi|ai_service|low|allow
deepseek.com|DeepSeek|ai_service|low|allow
doubao.com|字节豆包|ai_service|low|allow

# ===== VoIP / 协作 / 生产力（allow 或 block_soft） =====
zoom.us|Zoom|voip|medium|allow
skype.com|Skype|voip|medium|allow
discord.com|Discord|voip|low|allow
teams.microsoft.com|微软 Teams|voip|medium|allow
github.com|GitHub|developer_service|high|allow
gitlab.com|GitLab|developer_service|medium|allow
bitbucket.org|Bitbucket|developer_service|low|allow
npmjs.com|npm|developer_service|medium|allow
pypi.org|PyPI|developer_service|low|allow
docker.com|Docker|developer_service|medium|allow
docker.io|Docker|developer_service|medium|allow
notion.so|Notion|productivity|low|allow
slack.com|Slack|productivity|low|allow
atlassian.com|Atlassian|productivity|low|allow
trello.com|Trello|productivity|low|allow
airtable.com|Airtable|productivity|low|allow
foxmail.com|Foxmail|email|low|allow

# ===== 金融 / 教育 / 营销（allow 或 block_soft） =====
eastmoney.com|东方财富|finance|medium|allow
10jqka.com|同花顺|finance|low|allow
jr.alipay.com|蚂蚁金服|finance|medium|allow
icourse163.org|中国大学 MOOC|education|low|allow
xueersi.com|学而思|education|low|allow
zuoyebang.com|作业帮|education|low|allow
mailchimp.com|Mailchimp|marketing|low|block_soft
hubspot.com|HubSpot|marketing|low|block_soft
salesforce.com|Salesforce|marketing|low|block_soft
marketo.com|Marketo|marketing|low|block_soft

# ===== 第二批（国际 / 长尾真实域名，降低与现库重复损耗） =====
bose.com|Bose|iot_core|medium|allow
sonos.com|Sonos|iot_core|medium|allow
jbl.com|JBL|iot_core|low|allow
harmankardon.com|Harman Kardon|iot_core|low|allow
logitech.com|Logitech|iot_core|medium|allow
razer.com|Razer|iot_core|low|allow
corsair.com|Corsair|iot_core|low|allow
brother.com|Brother|iot_core|medium|allow
epson.com|Epson|iot_core|medium|allow
canon.com|Canon|iot_core|medium|allow
hp.com|惠普 HP|iot_core|high|allow
xerox.com|富士施乐|iot_core|medium|allow
dell.com|Dell|iot_core|high|allow
acer.com|Acer|iot_core|medium|allow
msi.com|MSI|iot_core|low|allow
gigabyte.com|Gigabyte|iot_core|low|allow
seagate.com|Seagate|iot_core|medium|allow
wd.com|Western Digital|iot_core|medium|allow
toshiba.com|东芝|iot_core|medium|allow
sharp.com|夏普|iot_core|medium|allow
electrolux.com|Electrolux|iot_core|low|allow
whirlpool.com|Whirlpool|iot_core|low|allow
bosch.com|博世|iot_core|medium|allow
siemens.com|西门子|iot_core|medium|allow
miele.com|Miele|iot_core|low|allow
beko.com|Beko|iot_core|low|allow
delonghi.com|De'Longhi|iot_core|low|allow
nespresso.com|Nespresso|iot_core|low|allow
keurig.com|Keurig|iot_core|low|allow
breville.com|Breville|iot_core|low|allow
kitchenaid.com|KitchenAid|iot_core|low|allow
sharkclean.com|Shark|iot_core|low|allow
bissell.com|Bissell|iot_core|low|allow
neato.com|Neato|iot_core|low|allow
vatti.com|华帝|iot_core|low|allow
galanz.com|格兰仕|iot_core|low|allow
aux.com|奥克斯|iot_core|low|allow
chigo.com|志高|iot_core|low|allow
little-swan.com|小天鹅|iot_core|low|allow
vanward.com|万和|iot_core|low|allow
macro.com|万家乐|iot_core|low|allow
sakura.com.cn|樱花|iot_core|low|allow
canbo.com|康宝|iot_core|low|allow
royalstar.com.cn|美菱|iot_core|low|allow
bmw.com|BMW|iot_core|high|allow
mercedes-benz.com|梅赛德斯-奔驰|iot_core|high|allow
audi.com|Audi|iot_core|high|allow
volvo.com|沃尔沃|iot_core|high|allow
ford.com|Ford|iot_core|high|allow
gm.com|通用汽车|iot_core|medium|allow
chevrolet.com|雪佛兰|iot_core|low|allow
toyota.com|丰田|iot_core|high|allow
honda.com|本田|iot_core|high|allow
nissan.com|日产|iot_core|medium|allow
hyundai.com|现代|iot_core|medium|allow
kia.com|起亚|iot_core|medium|allow
mazda.com|马自达|iot_core|low|allow
subaru.com|斯巴鲁|iot_core|low|allow
volkswagen.com|大众汽车|iot_core|high|allow
vw.com|大众|iot_core|high|allow
porsche.com|保时捷|iot_core|medium|allow
ferrari.com|法拉利|iot_core|low|allow
lamborghini.com|兰博基尼|iot_core|low|allow
bentley.com|宾利|iot_core|low|allow
jaguar.com|捷豹|iot_core|low|allow
landrover.com|路虎|iot_core|low|allow
mini.com|MINI|iot_core|low|allow
smart.com|smart|iot_core|low|allow
geely.com|吉利|iot_core|medium|allow
gwm.com|长城汽车|iot_core|medium|allow
changan.com|长安汽车|iot_core|medium|allow
baic.com|北汽|iot_core|low|allow
jac.com.cn|江淮汽车|iot_core|low|allow
chery.com|奇瑞|iot_core|medium|allow
netflix.com|Netflix|ott|high|allow
hulu.com|Hulu|ott|low|allow
disney.com|Disney+|ott|high|allow
hbomax.com|HBO Max|ott|low|allow
peacocktv.com|Peacock|ott|low|allow
paramountplus.com|Paramount+|ott|low|allow
spotify.com|Spotify|ott|high|allow
crunchyroll.com|Crunchyroll|ott|low|allow
twitch.tv|Twitch|ott|medium|allow
vimeo.com|Vimeo|ott|low|allow
dailymotion.com|DailyMotion|ott|low|allow
vevo.com|Vevo|ott|low|allow
pluto.tv|Pluto TV|ott|low|allow
tubi.tv|Tubi|ott|low|allow
roku.com|Roku|ott|medium|allow
fubo.tv|FuboTV|ott|low|allow
starz.com|Starz|ott|low|allow
showtime.com|Showtime|ott|low|allow
signal.org|Signal|social|low|allow
viber.com|Viber|messaging|low|allow
kakao.com|Kakao|social|low|allow
mastodon.social|Mastodon|social|low|allow
truthsocial.com|Truth Social|social|low|allow
mewe.com|MeWe|social|low|allow
liveramp.com|LiveRamp|advertising|low|block_soft
lotame.com|Lotame|advertising|low|block_soft
openx.com|OpenX|advertising|low|block_soft
indexexchange.com|Index Exchange|advertising|low|block_soft
triplelift.com|TripleLift|advertising|low|block_soft
sovrn.com|Sovrn|advertising|low|block_soft
mediamath.com|MediaMath|advertising|low|block_soft
beeswax.com|Beeswax|advertising|low|block_soft
intercom.com|Intercom|developer_service|low|block_soft
zendesk.com|Zendesk|developer_service|low|block_soft
livechat.com|LiveChat|developer_service|low|block_soft
tawk.to|Tawk.to|developer_service|low|block_soft
drift.com|Drift|marketing|low|block_soft
scaleway.com|Scaleway|cloud|low|allow
ovh.com|OVH|cloud|low|allow
hetzner.com|Hetzner|cloud|low|allow
namecheap.com|Namecheap|cloud|low|allow
godaddy.com|GoDaddy|cloud|low|allow
rackspace.com|Rackspace|cloud|low|allow
upcloud.com|UpCloud|cloud|low|allow
contabo.com|Contabo|cloud|low|allow
ionos.com|IONOS|cloud|low|allow
dreamhost.com|DreamHost|cloud|low|allow
bluehost.com|Bluehost|cloud|low|allow
hostgator.com|HostGator|cloud|low|allow
siteground.com|SiteGround|cloud|low|allow
wpengine.com|WP Engine|cloud|low|allow
cloudways.com|Cloudways|cloud|low|allow
ebay.com|eBay|shopping|high|allow
walmart.com|Walmart|shopping|medium|allow
target.com|Target|shopping|low|allow
bestbuy.com|Best Buy|shopping|low|allow
etsy.com|Etsy|shopping|low|allow
shopify.com|Shopify|shopping|medium|allow
aliexpress.com|AliExpress|shopping|high|allow
costco.com|Costco|shopping|low|allow
rakuten.com|Rakuten|shopping|low|allow
mercari.com|Mercari|shopping|low|allow
wayfair.com|Wayfair|shopping|low|allow
houzz.com|Houzz|shopping|low|allow
newegg.com|Newegg|shopping|medium|allow
bhphotovideo.com|B&H|shopping|low|allow
macys.com|Macy's|shopping|low|allow
nordstrom.com|Nordstrom|shopping|low|allow
alibaba.com|阿里巴巴|shopping|high|allow
paypal.com|PayPal|finance|high|allow
stripe.com|Stripe|finance|medium|allow
squareup.com|Square|finance|low|allow
adyen.com|Adyen|finance|low|allow
braintree.com|Braintree|finance|low|allow
venmo.com|Venmo|finance|low|allow
plaid.com|Plaid|finance|low|allow
wise.com|Wise|finance|low|allow
revolut.com|Revolut|finance|low|allow
chime.com|Chime|finance|low|allow
americanexpress.com|American Express|finance|medium|allow
visa.com|Visa|finance|high|allow
mastercard.com|Mastercard|finance|high|allow
discover.com|Discover|finance|low|allow
capitalone.com|Capital One|finance|low|allow
bankofamerica.com|Bank of America|finance|low|allow
chase.com|Chase|finance|low|allow
citi.com|Citibank|finance|low|allow
wellsfargo.com|Wells Fargo|finance|low|allow
hsbc.com|HSBC|finance|low|allow
barclays.com|Barclays|finance|low|allow
icbc.com|工商银行|finance|high|allow
ccb.com|建设银行|finance|high|allow
abchina.com|农业银行|finance|high|allow
boc.cn|中国银行|finance|high|allow
cmbchina.com|招商银行|finance|high|allow
cib.com.cn|兴业银行|finance|medium|allow
spdb.com|浦发银行|finance|medium|allow
pingan.com|平安银行|finance|medium|allow
citic.com|中信银行|finance|medium|allow
cebbank.com|光大银行|finance|low|allow
cmbc.com|民生银行|finance|low|allow
psbc.com|邮储银行|finance|medium|allow
webank.com|微众银行|finance|low|allow
duxiaoman.com|度小满|finance|low|allow
lu.com|陆金所|finance|low|allow
ppdai.com|拍拍贷|finance|low|allow
bestpay.com.cn|翼支付|finance|low|allow
nytimes.com|纽约时报|news|low|allow
washingtonpost.com|华盛顿邮报|news|low|allow
bbc.co.uk|BBC|news|low|allow
theguardian.com|卫报|news|low|allow
reuters.com|路透|news|low|allow
bloomberg.com|彭博|news|low|allow
wsj.com|华尔街日报|news|low|allow
cnn.com|CNN|news|low|allow
fox.com|Fox|news|low|allow
forbes.com|Forbes|news|low|allow
techcrunch.com|TechCrunch|news|low|allow
theverge.com|The Verge|news|low|allow
wired.com|Wired|news|low|allow
arstechnica.com|Ars Technica|news|low|allow
engadget.com|Engadget|news|low|allow
cnet.com|CNET|news|low|allow
mashable.com|Mashable|news|low|allow
vox.com|Vox|news|low|allow
economist.com|经济学人|news|low|allow
ft.com|金融时报|news|low|allow
roblox.com|Roblox|gaming|medium|allow
minecraft.net|Minecraft|gaming|low|allow
square-enix.com|Square Enix|gaming|low|allow
sega.com|Sega|gaming|low|allow
bandainamco.com|Bandai Namco|gaming|low|allow
capcom.com|Capcom|gaming|low|allow
konami.com|Konami|gaming|low|allow
take2games.com|Take-Two|gaming|low|allow
activision.com|Activision|gaming|low|allow
zynga.com|Zynga|gaming|low|allow
supercell.com|Supercell|gaming|low|allow
king.com|King|gaming|low|allow
gameloft.com|Gameloft|gaming|low|allow
coursera.org|Coursera|education|low|allow
edx.org|edX|education|low|allow
khanacademy.org|Khan Academy|education|low|allow
udemy.com|Udemy|education|low|allow
udacity.com|Udacity|education|low|allow
duolingo.com|Duolingo|education|low|allow
chegg.com|Chegg|education|low|allow
quizlet.com|Quizlet|education|low|allow
brainly.com|Brainly|education|low|allow
byjus.com|BYJU'S|education|low|allow
skillshare.com|Skillshare|education|low|allow
masterclass.com|MasterClass|education|low|allow
brilliant.org|Brilliant|education|low|allow
codecademy.com|Codecademy|education|low|allow
freecodecamp.org|freeCodeCamp|education|low|allow
asana.com|Asana|productivity|low|allow
monday.com|Monday.com|productivity|low|allow
clickup.com|ClickUp|productivity|low|allow
dropbox.com|Dropbox|productivity|medium|allow
box.com|Box|productivity|low|allow
evernote.com|Evernote|productivity|low|allow
todoist.com|Todoist|productivity|low|allow
basecamp.com|Basecamp|productivity|low|allow
smartsheet.com|Smartsheet|productivity|low|allow
miro.com|Miro|productivity|low|allow
figma.com|Figma|productivity|low|allow
canva.com|Canva|productivity|low|allow
webex.com|Webex|productivity|low|allow
goto.com|GoTo|productivity|low|allow
teamviewer.com|TeamViewer|productivity|low|allow
anydesk.com|AnyDesk|productivity|low|allow
maven.apache.org|Apache Maven|developer_service|low|allow
jenkins.io|Jenkins|developer_service|low|allow
circleci.com|CircleCI|developer_service|low|allow
jfrog.com|JFrog|developer_service|low|allow
sonatype.com|Sonatype|developer_service|low|allow
snyk.io|Snyk|developer_service|low|allow
codecov.io|Codecov|developer_service|low|allow
coveralls.io|Coveralls|developer_service|low|allow
sonarqube.org|SonarQube|developer_service|low|allow
datadog.com|Datadog|developer_service|low|allow
newrelic.com|New Relic|developer_service|low|allow
grafana.com|Grafana|developer_service|low|allow
prometheus.io|Prometheus|developer_service|low|allow
elastic.co|Elastic|developer_service|low|allow
splunk.com|Splunk|developer_service|low|allow
pagerduty.com|PagerDuty|developer_service|low|allow
opsgenie.com|OpsGenie|developer_service|low|allow
kaspersky.com|卡巴斯基|developer_service|low|allow
norton.com|Norton|developer_service|low|allow
mcafee.com|McAfee|developer_service|low|allow
avast.com|Avast|developer_service|low|allow
avg.com|AVG|developer_service|low|allow
bitdefender.com|Bitdefender|developer_service|low|allow
eset.com|ESET|developer_service|low|allow
malwarebytes.com|Malwarebytes|developer_service|low|allow
trendmicro.com|Trend Micro|developer_service|low|allow
f-secure.com|F-Secure|developer_service|low|allow
sophos.com|Sophos|developer_service|low|allow
nordvpn.com|NordVPN|developer_service|low|allow
expressvpn.com|ExpressVPN|developer_service|low|allow
proton.me|Proton|developer_service|low|allow
mullvad.net|Mullvad|developer_service|low|allow
surfshark.com|Surfshark|developer_service|low|allow
windscribe.com|Windscribe|developer_service|low|allow
cyberghost.com|CyberGhost|developer_service|low|allow
douyu.com|斗鱼|ott|low|allow
huya.com|虎牙|ott|low|allow
yy.com|YY|ott|low|allow
inke.com|映客|social|low|allow
tongcheng.com|同程旅行|travel|low|allow
mafengwo.com|马蜂窝|travel|low|allow
tuniu.com|途牛|travel|low|allow
guazi.com|瓜子二手车|shopping|low|allow
renrenche.com|人人车|shopping|low|allow
bitauto.com|易车|shopping|low|allow
autohome.com.cn|汽车之家|shopping|low|allow
dongchedi.com|懂车帝|shopping|low|allow
pcauto.com.cn|太平洋汽车|shopping|low|allow
smzdm.com|什么值得买|shopping|low|allow
dangdang.com|当当|shopping|low|allow
gome.com|国美|shopping|low|allow
alimama.com|阿里妈妈|advertising|low|block_soft

# ===== 第三批（补差破 5000，真实长尾域名） =====
leapmotor.com|零跑汽车|iot_core|low|allow
polestar.com|Polestar|iot_core|low|allow
lucid.com|Lucid|iot_core|low|allow
rivian.com|Rivian|iot_core|low|allow
genesis.com|Genesis|iot_core|low|allow
lexus.com|Lexus|iot_core|low|allow
infiniti.com|Infiniti|iot_core|low|allow
acura.com|Acura|iot_core|low|allow
buick.com|Buick|iot_core|low|allow
cadillac.com|Cadillac|iot_core|low|allow
jeep.com|Jeep|iot_core|low|allow
gmc.com|GMC|iot_core|low|allow
ram.com|Ram|iot_core|low|allow
chrysler.com|Chrysler|iot_core|low|allow
dodge.com|Dodge|iot_core|low|allow
china-life.com.cn|中国人寿|finance|low|allow
cpic.com.cn|太平洋保险|finance|low|allow
picc.com.cn|中国人保|finance|low|allow
taikang.com|泰康|finance|low|allow
nci.com.cn|新华人寿|finance|low|allow
bankofbeijing.com.cn|北京银行|finance|low|allow
hzbank.com.cn|杭州银行|finance|low|allow
jsbchina.cn|江苏银行|finance|low|allow
nib.com.cn|宁波银行|finance|low|allow
cbhb.cn|渤海银行|finance|low|allow
shein.com|SHEIN|shopping|low|allow
farfetch.com|Farfetch|shopping|low|allow
zalando.com|Zalando|shopping|low|allow
asos.com|ASOS|shopping|low|allow
boohoo.com|Boohoo|shopping|low|allow
huggingface.co|Hugging Face|ai_service|low|allow
replicate.com|Replicate|ai_service|low|allow
stability.ai|Stability AI|ai_service|low|allow
midjourney.com|Midjourney|ai_service|low|allow
perplexity.ai|Perplexity|ai_service|low|allow
cohere.com|Cohere|ai_service|low|allow
character.ai|Character.AI|ai_service|low|allow
poe.com|Poe|ai_service|low|allow
mistral.ai|Mistral|ai_service|low|allow
calendly.com|Calendly|productivity|low|allow
docusign.com|DocuSign|productivity|low|allow
typeform.com|Typeform|productivity|low|allow
jotform.com|JotForm|productivity|low|allow
surveymonkey.com|SurveyMonkey|productivity|low|allow
redis.io|Redis|developer_service|low|allow
mongodb.com|MongoDB|developer_service|low|allow
postgresql.org|PostgreSQL|developer_service|low|allow
kubernetes.io|Kubernetes|developer_service|low|allow
hashicorp.com|HashiCorp|developer_service|low|allow
terraform.io|Terraform|developer_service|low|allow
supabase.com|Supabase|developer_service|low|allow
marketwatch.com|MarketWatch|news|low|allow
seekingalpha.com|Seeking Alpha|news|low|allow
investopedia.com|Investopedia|news|low|allow
billboard.com|Billboard|news|low|allow
rollingstone.com|Rolling Stone|news|low|allow
variety.com|Variety|news|low|allow
huajiao.com|花椒直播|ott|low|allow
"""

FIELDS = ["domain", "organization", "category", "confidence", "description", "action", "side_effects"]

CAT_CN = {
    "iot_core": "设备云/控制通道",
    "analytics": "用户行为分析",
    "advertising": "广告与营销",
    "advertising_sdk": "广告 SDK",
    "tracker": "用户追踪",
    "social": "社交与画像",
    "telemetry": "设备遥测",
    "cdn": "CDN 加速",
    "cloud": "云服务",
    "cloud_storage": "云存储",
    "messaging": "即时通讯",
    "ott": "视频/OTT",
    "os_update": "系统更新",
    "system_update": "系统更新",
    "app_update": "应用更新",
    "map": "地图服务",
    "shopping": "电商/生活",
    "search": "搜索",
    "voip": "网络电话",
    "developer_service": "开发者服务",
    "ai_service": "AI 服务",
    "machine_learning": "机器学习",
    "finance": "金融",
    "news": "新闻门户",
    "gaming": "游戏",
    "productivity": "生产力协作",
    "marketing": "营销",
    "email": "邮件",
    "travel": "出行旅行",
    "education": "教育",
}

# block 类副作用文案，与 expand_homeward_kb.py 的 S_* 一致
SIDE_BY_CAT = {
    "analytics": "行为分析与崩溃统计停止；不影响应用核心功能",
    "advertising": "广告/营销与追踪被拦截；应用内广告与推荐位停止，不影响功能",
    "advertising_sdk": "广告/营销与追踪被拦截；应用内广告与推荐位停止，不影响功能",
    "tracker": "追踪/广告或恶意通信被拦截；统计、个性化推荐与广告失效，通常不影响核心功能",
    "social": "社交追踪/画像与分享回调用被拦截；第三方登录可能降级，不影响主功能",
    "telemetry": "设备匿名遥测/体验计划上报停止；不影响设备核心联网与控制",
}

DOMAIN_RE = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$")


def parse():
    rows = []
    seen = set()
    dups = 0
    bad = []
    for ln in RAW.splitlines():
        ln = ln.strip()
        if not ln or ln.startswith("#"):
            continue
        parts = [p.strip() for p in ln.split("|")]
        if len(parts) != 5:
            bad.append((ln, "字段数!=5"))
            continue
        domain, org, cat, conf, action = parts
        domain = domain.lower()
        if not DOMAIN_RE.match(domain):
            bad.append((domain, "域名格式非法"))
            continue
        if domain in seen:
            dups += 1
            continue
        seen.add(domain)
        if action == "allow":
            side = ""
            desc = f"{org} {CAT_CN.get(cat, cat)}"
        else:
            side = SIDE_BY_CAT.get(cat, "追踪/广告或恶意通信被拦截；统计、个性化推荐与广告失效，通常不影响核心功能")
            desc = f"{org} {CAT_CN.get(cat, cat)}"
        rows.append({
            "domain": domain, "organization": org, "category": cat,
            "confidence": conf, "description": desc, "action": action,
            "side_effects": side,
        })
    return rows, dups, bad


def main():
    rows, dups, bad = parse()
    print(f"解析条目：{len(rows)} 条（去重跳过 {dups} 条）")
    if bad:
        print(f"⚠️ 非法条目 {len(bad)} 条：")
        for b in bad:
            print("   ", b)
        if any("域名格式非法" in m for _, m in bad):
            print("存在非法域名，终止。")
            sys.exit(2)
    if "--check" in sys.argv:
        print("(--check 模式，未写文件)")
        return
    with OUT.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=FIELDS)
        w.writeheader()
        w.writerows(rows)
    print(f"已写出 {OUT.name}：{len(rows)} 条")


if __name__ == "__main__":
    main()
