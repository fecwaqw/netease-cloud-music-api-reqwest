//
// mod.rs
// Copyright (C) 2019 gmg137 <gmg137@live.com>
// Copyright (C) 2026 fecwaqw <fecwaqw@126.com>
// Distributed under terms of the GPLv3 license.
//
mod encrypt;
pub(crate) mod model;
use anyhow::{anyhow, Result};
use chrono::Utc;
use cookie_store::CookieStore;
use encrypt::Crypto;
use lazy_static::lazy_static;
pub use model::*;
use regex::Regex;
use reqwest::{self, header::HeaderMap, Client};
use reqwest_cookie_store::CookieStoreMutex;
use std::{
    collections::HashMap,
    sync::{Arc, OnceLock},
    time::Duration,
};
use url::Url;
use urlqstring::QueryParams;
lazy_static! {
    static ref _CSRF: Regex = Regex::new(r"_csrf=(?P<csrf>[^(;|$)]+)").unwrap();
}

static DOMAIN: &'static str = "https://music.163.com";
static API_DOMAIN: &'static str = "http://interface.music.163.com";

const TIMEOUT: u64 = 100;

const LINUX_USER_AGNET: &str =
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.90 Safari/537.36";

const USER_AGENT_LIST: [&str; 14] = [
    "Mozilla/5.0 (iPhone; CPU iPhone OS 9_1 like Mac OS X) AppleWebKit/601.1.46 (KHTML, like Gecko) Version/9.0 Mobile/13B143 Safari/601.1",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 9_1 like Mac OS X) AppleWebKit/601.1.46 (KHTML, like Gecko) Version/9.0 Mobile/13B143 Safari/601.1",
    "Mozilla/5.0 (Linux; Android 5.0; SM-G900P Build/LRX21T) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.115 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.115 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 5.1.1; Nexus 6 Build/LYZ28E) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.115 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 10_3_2 like Mac OS X) AppleWebKit/603.2.4 (KHTML, like Gecko) Mobile/14F89;GameHelper",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 10_0 like Mac OS X) AppleWebKit/602.1.38 (KHTML, like Gecko) Version/10.0 Mobile/14A300 Safari/602.1",
    "Mozilla/5.0 (iPad; CPU OS 10_0 like Mac OS X) AppleWebKit/602.1.38 (KHTML, like Gecko) Version/10.0 Mobile/14A300 Safari/602.1",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.12; rv:46.0) Gecko/20100101 Firefox/46.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.115 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_5) AppleWebKit/603.2.4 (KHTML, like Gecko) Version/10.1.1 Safari/603.2.4",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:46.0) Gecko/20100101 Firefox/46.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/13.1058",
];

#[derive(Clone)]
pub struct MusicApi {
    client: reqwest::Client,
    cookie_jar: Arc<CookieStoreMutex>,
    csrf: OnceLock<String>,
    max_cons: usize,
}

#[allow(unused)]
enum CryptoApi {
    Weapi,
    LinuxApi,
    Eapi,
}

impl Default for MusicApi {
    fn default() -> Self {
        Self::new(0)
    }
}

impl MusicApi {
    #[allow(unused)]
    pub fn new(max_cons: usize) -> Self {
        let cookie_jar = Arc::new(CookieStoreMutex::default());
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(TIMEOUT))
            .pool_max_idle_per_host(max_cons)
            .cookie_store(true)
            .cookie_provider(cookie_jar.clone())
            .build()
            .expect("初始化网络请求失败!");
        Self {
            client,
            cookie_jar,
            csrf: OnceLock::new(),
            max_cons,
        }
    }

    #[allow(unused)]
    pub fn from_cookie_jar(cookie_jar: CookieStore, max_cons: usize) -> Self {
        let cookie_jar = Arc::new(CookieStoreMutex::new(cookie_jar));
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(TIMEOUT))
            .pool_max_idle_per_host(max_cons)
            .cookie_store(true)
            .cookie_provider(cookie_jar.clone())
            .build()
            .expect("初始化网络请求失败!");
        Self {
            client,
            cookie_jar,
            csrf: OnceLock::new(),
            max_cons,
        }
    }

    #[allow(unused)]
    pub fn cookie_jar(&self) -> Arc<CookieStoreMutex> {
        self.cookie_jar.clone()
    }

    /// 设置使用代理
    /// proxy: 代理地址，支持以下协议
    ///   - http: Proxy. Default when no scheme is specified.
    ///   - https: HTTPS Proxy. (Added in 7.52.0 for OpenSSL, GnuTLS and NSS)
    ///   - socks4: SOCKS4 Proxy.
    ///   - socks4a: SOCKS4a Proxy. Proxy resolves URL hostname.
    ///   - socks5: SOCKS5 Proxy.
    ///   - socks5h: SOCKS5 Proxy. Proxy resolves URL hostname.
    pub fn set_proxy(&mut self, proxy: reqwest::Proxy) -> Result<()> {
        self.client = Client::builder()
            .proxy(proxy)
            .timeout(Duration::from_secs(TIMEOUT))
            .pool_max_idle_per_host(self.max_cons)
            .cookie_store(true)
            .cookie_provider(self.cookie_jar())
            .build()
            .expect("初始化网络请求失败!");
        Ok(())
    }
    fn get_cookie<'a>(&self, url: &Url, name: &str) -> Option<String> {
        let cookie = self.cookie_jar();
        let cookie: std::sync::MutexGuard<'_, CookieStore> = cookie.lock().unwrap();
        for (key, value) in cookie.get_request_values(url) {
            if key == name {
                return Some(value.to_string());
            }
        }
        return None;
    }
    /// 发送请求
    /// method: 请求方法
    /// path: 请求路径
    /// params: 请求参数
    /// cryptoapi: 请求加密方式
    /// ua: 要使用的 USER_AGENT_LIST
    /// append_csrf: 是否在路径中添加 csrf
    async fn request(
        &self,
        method: Method,
        path: &str,
        params: HashMap<&str, &str>,
        cryptoapi: CryptoApi,
        ua: &str,
        append_csrf: bool,
    ) -> Result<String> {
        let empty = String::new();
        let csrf = match self.csrf.get() {
            Some(str) => str.clone(),
            None => {
                if let Some(str) = self.get_cookie(&DOMAIN.parse().unwrap(), "__csrf") {
                    self.csrf.get_or_init(|| str);
                }
                self.csrf.get().unwrap_or(&empty).clone()
            }
        };
        let mut url = String::new();
        match method {
            Method::Post => {
                let mut headers = HeaderMap::new();
                let encrypted_data = match cryptoapi {
                    CryptoApi::Weapi => {
                        let mut data = HashMap::from(params);
                        headers.append("Referer", DOMAIN.parse().unwrap());
                        headers.append("User-Agent", choose_user_agent(ua).parse().unwrap());
                        headers.append(
                            "Host",
                            Url::parse(DOMAIN)
                                .unwrap()
                                .host_str()
                                .unwrap()
                                .parse()
                                .unwrap(),
                        );
                        if append_csrf {
                            data.insert("csrf_token", &csrf);
                        }
                        url = format!("{}{}", DOMAIN, path);
                        Crypto::weapi(&QueryParams::from(data).json())
                    }
                    CryptoApi::LinuxApi => {
                        headers.append("User-Agent", LINUX_USER_AGNET.parse().unwrap());
                        headers.append(
                            "Host",
                            Url::parse(DOMAIN)
                                .unwrap()
                                .host_str()
                                .unwrap()
                                .parse()
                                .unwrap(),
                        );
                        let data = format!(
                            r#"{{"method":"POST","url":"{}{}","params":{}}}"#,
                            DOMAIN,
                            path,
                            QueryParams::from_map(params).json()
                        );
                        url = format!("{}{}", DOMAIN, "/api/linux/forward");
                        Crypto::linuxapi(&data)
                    }
                    CryptoApi::Eapi => {
                        let now = Utc::now().timestamp().to_string();
                        let cookie_jar = self.cookie_jar();
                        let cookie_jar = cookie_jar.lock().unwrap();
                        let mut header_cookie: HashMap<String, String> = cookie_jar
                            .get_request_values(&format!("{}{}", API_DOMAIN, path).parse().unwrap())
                            .map(|(key, value)| (key.to_string(), value.to_string()))
                            .collect();
                        let key_defaults = HashMap::from([
                            ("osver", None),
                            ("deviceId", None),
                            ("os", None),
                            ("appver", None),
                            ("versioncode", Some("140")),
                            ("mobilename", Some("")),
                            ("buildver", Some(&now[0..9])),
                            ("resolution", Some("1920x1080")),
                            ("channel", None),
                            ("MUSIC_U", None),
                            ("MUSIC_A", None),
                        ]);
                        header_cookie.remove("__csrf");
                        for (key, default) in &key_defaults {
                            match header_cookie.get(*key) {
                                Some(_) => {}
                                None if matches!(default, Some(_)) => {
                                    header_cookie
                                        .insert((*key).to_string(), String::from(default.unwrap()));
                                }
                                None => {}
                            }
                        }
                        if append_csrf {
                            header_cookie.insert("__csrf".to_string(), csrf.clone());
                        }
                        header_cookie.insert("requestId".to_string(), generate_request_id());
                        headers.append(
                            "Host",
                            Url::parse(API_DOMAIN)
                                .unwrap()
                                .host_str()
                                .unwrap()
                                .parse()
                                .unwrap(),
                        );
                        headers.append("User-Agent", choose_user_agent(ua).parse().unwrap());
                        headers.append(
                            "Cookie",
                            header_cookie
                                .iter()
                                .map(|(key, value)| format!("{}={}", key, value))
                                .collect::<Vec<_>>()
                                .join("; ")
                                .parse()
                                .unwrap(),
                        );

                        url = format!("{}{}", API_DOMAIN, path);
                        let mut data = HashMap::from(params);
                        data.insert("e_r", "False");
                        let eapi_path = path.replacen("eapi", "api", 1);
                        Crypto::eapi(&eapi_path, &QueryParams::from_map(data).json())
                    }
                };
                let response = self
                    .client
                    .post(url)
                    .headers(headers)
                    .header("Accept", "*/*")
                    .header("Accept-Language", "en-US,en;q=0.5")
                    .header("Connection", "keep-alive")
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .body(encrypted_data)
                    .send()
                    .await
                    .map_err(|_| anyhow!("none"))?;
                response.text().await.map_err(|_| anyhow!("none"))
            }
            Method::Get => self
                .client
                .get(url)
                .send()
                .await
                .map_err(|_| anyhow!("none"))?
                .text()
                .await
                .map_err(|_| anyhow!("none")),
        }
    }

    /// 登录
    /// username: 用户名(邮箱或手机)
    /// password: 密码
    #[allow(unused)]
    pub async fn login(&self, username: String, password: String) -> Result<LoginInfo> {
        let mut params = HashMap::new();
        let path;
        if username.len().eq(&11) && username.parse::<u64>().is_ok() {
            path = "/weapi/login/cellphone";
            params.insert("phone", &username[..]);
            params.insert("password", &password[..]);
            params.insert("rememberLogin", "true");
        } else {
            let client_token =
                "1_jVUMqWEPke0/1/Vu56xCmJpo5vP1grjn_SOVVDzOc78w8OKLVZ2JH7IfkjSXqgfmh";
            path = "/weapi/login";
            params.insert("username", &username[..]);
            params.insert("password", &password[..]);
            params.insert("rememberLogin", "true");
            params.insert("clientToken", client_token);
        }
        let result = self
            .request(Method::Post, path, params, CryptoApi::Weapi, "", true)
            .await?;
        to_login_info(result)
    }

    /// 手机号登录
    /// ctcode: 国家码，用于国外手机号登录
    /// phone: 手机号码
    /// captcha: 验证码
    #[allow(unused)]
    pub async fn login_cellphone(
        &self,
        ctcode: String,
        phone: String,
        captcha: String,
    ) -> Result<LoginInfo> {
        let path = "/weapi/login/cellphone";
        let mut params = HashMap::new();
        params.insert("phone", &phone[..]);
        params.insert("countrycode", &ctcode[..]);
        params.insert("captcha", &captcha[..]);
        params.insert("rememberLogin", "true");
        let result = self
            .request(Method::Post, path, params, CryptoApi::Weapi, "", true)
            .await?;
        to_login_info(result)
    }

    /// 获取验证码
    /// ctcode: 国家码，用于国外手机号登录
    /// phone: 手机号码
    #[allow(unused)]
    pub async fn captcha(&self, ctcode: String, phone: String) -> Result<()> {
        let path = "/weapi/sms/captcha/sent";
        let mut params = HashMap::new();
        params.insert("cellphone", &phone[..]);
        params.insert("ctcode", &ctcode[..]);
        let result = self
            .request(Method::Post, path, params, CryptoApi::Weapi, "", true)
            .await?;
        to_captcha(result)
    }

    /// 创建登陆二维码链接
    /// 返回(qr_url, unikey)
    #[allow(unused)]
    pub async fn login_qr_create(&self) -> Result<(String, String)> {
        let path = "/weapi/login/qrcode/unikey";
        let mut params = HashMap::new();
        params.insert("type", "1");
        let result = self
            .request(Method::Post, path, params, CryptoApi::Weapi, "", true)
            .await?;
        let unikey = to_unikey(result)?;
        Ok((
            format!("https://music.163.com/login?codekey={}", &unikey),
            unikey,
        ))
    }

    /// 检查登陆二维码
    /// key: 由 login_qr_create 生成的 unikey
    #[allow(unused)]
    pub async fn login_qr_check(&self, key: String) -> Result<Msg> {
        let path = "/weapi/login/qrcode/client/login";
        let mut params = HashMap::new();
        params.insert("type", "1");
        params.insert("key", &key);
        let result = self
            .request(Method::Post, path, params, CryptoApi::Weapi, "", true)
            .await?;
        to_message(result)
    }

    /// 登录状态
    #[allow(unused)]
    pub async fn login_status(&self) -> Result<LoginInfo> {
        let path = "/api/nuser/account/get";
        let result = self
            .request(
                Method::Post,
                path,
                HashMap::new(),
                CryptoApi::Weapi,
                "",
                true,
            )
            .await?;
        to_login_info(result)
    }

    /// 退出
    #[allow(unused)]
    pub async fn logout(&self) {
        let path = "https://music.163.com/weapi/logout";
        self.request(
            Method::Post,
            path,
            HashMap::new(),
            CryptoApi::Weapi,
            "pc",
            true,
        )
        .await;
    }

    /// 每日签到
    #[allow(unused)]
    pub async fn daily_task(&self) -> Result<Msg> {
        let path = "/weapi/point/dailyTask";
        let mut params = HashMap::new();
        params.insert("type", "0");
        let result = self
            .request(Method::Post, path, params, CryptoApi::Weapi, "", true)
            .await?;
        to_msg(result)
    }

    /// 用户喜欢音乐id列表
    /// uid: 用户id
    #[allow(unused)]
    pub async fn user_song_id_list(&self, uid: u64) -> Result<Vec<u64>> {
        let path = "/weapi/song/like/get";
        let mut params = HashMap::new();
        let uid = uid.to_string();
        params.insert("uid", uid.as_str());
        let result = self
            .request(Method::Post, path, params, CryptoApi::Weapi, "", true)
            .await?;
        to_song_id_list(result)
    }

    /// 用户歌单
    /// uid: 用户id
    /// offset: 列表起点号
    /// limit: 列表长度
    #[allow(unused)]
    pub async fn user_song_list(&self, uid: u64, offset: u16, limit: u16) -> Result<Vec<SongList>> {
        let path = "/weapi/user/playlist";
        let mut params = HashMap::new();
        let uid = uid.to_string();
        let offset = offset.to_string();
        let limit = limit.to_string();
        params.insert("uid", uid.as_str());
        params.insert("offset", offset.as_str());
        params.insert("limit", limit.as_str());
        let result = self
            .request(Method::Post, path, params, CryptoApi::Weapi, "", true)
            .await?;
        to_song_list(result, Parse::Usl)
    }

    /// 用户收藏专辑列表
    /// offset: 列表起点号
    /// limit: 列表长度
    #[allow(unused)]
    pub async fn album_sublist(&self, offset: u16, limit: u16) -> Result<Vec<SongList>> {
        let path = "/weapi/album/sublist";
        let mut params = HashMap::new();
        let offset = offset.to_string();
        let limit = limit.to_string();
        let total = true.to_string();
        params.insert("total", total.as_str());
        params.insert("offset", offset.as_str());
        params.insert("limit", limit.as_str());
        let result = self
            .request(Method::Post, path, params, CryptoApi::Weapi, "", true)
            .await?;
        to_song_list(result, Parse::LikeAlbum)
    }

    /// 用户云盘
    #[allow(unused)]
    pub async fn user_cloud_disk(&self) -> Result<Vec<SongInfo>> {
        let path = "/weapi/v1/cloud/get";
        let mut params = HashMap::new();
        params.insert("offset", "0");
        params.insert("limit", "10000");
        let result = self
            .request(Method::Post, path, params, CryptoApi::Weapi, "", true)
            .await?;
        to_song_info(result, Parse::Ucd)
    }

    /// 歌单详情
    /// songlist_id: 歌单 id
    #[allow(unused)]
    pub async fn song_list_detail(&self, songlist_id: u64) -> Result<PlayListDetail> {
        let empty = String::new();
        let csrf_token = self.csrf.get().unwrap_or(&empty);
        let path = "/weapi/v6/playlist/detail";
        let mut params = HashMap::new();
        let songlist_id = songlist_id.to_string();
        params.insert("id", songlist_id.as_str());
        params.insert("offset", "0");
        params.insert("total", "true");
        params.insert("limit", "1000");
        params.insert("n", "1000");
        params.insert("csrf_token", csrf_token);
        let result = self
            .request(Method::Post, path, params, CryptoApi::Weapi, "", true)
            .await?;
        to_mix_detail(&serde_json::from_str(&result)?)
    }

    /// 歌曲详情
    /// ids: 歌曲 id 列表
    #[allow(unused)]
    pub async fn songs_detail(&self, ids: &[u64]) -> Result<Vec<SongInfo>> {
        let path = "/weapi/v3/song/detail";
        let mut params = HashMap::new();
        let c = ids
            .iter()
            .map(|i| format!("{{\\\"id\\\":\\\"{}\\\"}}", i))
            .collect::<Vec<String>>()
            .join(",");
        let c = format!("[{}]", c);
        params.insert("c", &c[..]);
        let result = self
            .request(Method::Post, path, params, CryptoApi::Weapi, "", true)
            .await?;
        to_song_info(result, Parse::Usl)
    }

    /// 歌曲 URL
    /// ids: 歌曲列表
    /// level: 歌曲码率等级
    ///     higher: 较高
    ///     exhigh: 极高
    ///     lossless: 无损
    ///     hires: Hi-Res
    ///     jyeffect: 高清环绕声
    ///     sky: 沉浸环绕声
    ///     dolby: 杜比全景声
    ///     jymaster: 超清母带
    #[allow(unused)]
    pub async fn songs_url(&self, ids: &[u64], level: &str) -> Result<Vec<SongUrl>> {
        // 使用 Eapi 获取音乐
        let path = "/eapi/song/enhance/player/url/v1";
        let mut params = HashMap::new();
        let ids = serde_json::to_string(ids)?;
        params.insert("ids", ids.as_str());
        params.insert("level", level);
        params.insert("encodeType", "flac");
        if level == "sky" {
            params.insert("immerseType", "c51");
        }
        let result = self
            .request(Method::Post, path, params, CryptoApi::Eapi, "", true)
            .await?;
        to_song_url(result)
    }

    /// 每日推荐歌单
    #[allow(unused)]
    pub async fn recommend_resource(&self) -> Result<Vec<SongList>> {
        let path = "/weapi/v1/discovery/recommend/resource";
        let result = self
            .request(
                Method::Post,
                path,
                HashMap::new(),
                CryptoApi::Weapi,
                "",
                true,
            )
            .await?;
        to_song_list(result, Parse::Rmd)
    }

    /// 每日推荐歌曲
    #[allow(unused)]
    pub async fn recommend_songs(&self) -> Result<Vec<SongInfo>> {
        let path = "/weapi/v2/discovery/recommend/songs";
        let mut params = HashMap::new();
        params.insert("total", "ture");
        let result = self
            .request(Method::Post, path, params, CryptoApi::Weapi, "", true)
            .await?;
        to_song_info(result, Parse::Rmds)
    }

    /// 私人FM
    #[allow(unused)]
    pub async fn personal_fm(&self) -> Result<Vec<SongInfo>> {
        let path = "/weapi/v1/radio/get";
        let result = self
            .request(
                Method::Post,
                path,
                HashMap::new(),
                CryptoApi::Weapi,
                "",
                true,
            )
            .await?;
        to_song_info(result, Parse::Rmd)
    }

    /// 收藏/取消收藏
    /// songid: 歌曲id
    /// like: true 收藏，false 取消
    #[allow(unused)]
    pub async fn like(&self, like: bool, songid: u64) -> bool {
        let path = "/weapi/radio/like";
        let mut params = HashMap::new();
        let songid = songid.to_string();
        let like = like.to_string();
        params.insert("alg", "itembased");
        params.insert("trackId", songid.as_str());
        params.insert("like", like.as_str());
        params.insert("time", "25");
        if let Ok(result) = self
            .request(Method::Post, path, params, CryptoApi::Weapi, "", true)
            .await
        {
            return to_msg(result)
                .unwrap_or(Msg {
                    code: 0,
                    msg: "".to_owned(),
                })
                .code
                .eq(&200);
        }
        false
    }

    /// FM 不喜欢
    /// songid: 歌曲id
    #[allow(unused)]
    pub async fn fm_trash(&self, songid: u64) -> bool {
        let path = "/weapi/radio/trash/add";
        let mut params = HashMap::new();
        let songid = songid.to_string();
        params.insert("alg", "RT");
        params.insert("songId", songid.as_str());
        params.insert("time", "25");
        if let Ok(result) = self
            .request(Method::Post, path, params, CryptoApi::Weapi, "", true)
            .await
        {
            return to_msg(result)
                .unwrap_or(Msg {
                    code: 0,
                    msg: "".to_owned(),
                })
                .code
                .eq(&200);
        }
        false
    }

    /// 搜索
    /// keywords: 关键词
    /// types: 1: 单曲, 10: 专辑, 100: 歌手, 1000: 歌单, 1002: 用户, 1004: MV, 1006: 歌词, 1009: 电台, 1014: 视频
    /// offset: 起始点
    /// limit: 数量
    #[allow(unused)]
    pub async fn search(
        &self,
        keywords: String,
        types: u32,
        offset: u16,
        limit: u16,
    ) -> Result<String> {
        let path = "/weapi/search/get";
        let mut params = HashMap::new();
        let _types = types.to_string();
        let offset = offset.to_string();
        let limit = limit.to_string();
        params.insert("s", &keywords[..]);
        params.insert("type", &_types[..]);
        params.insert("offset", &offset[..]);
        params.insert("limit", &limit[..]);
        self.request(Method::Post, path, params, CryptoApi::Weapi, "", true)
            .await
    }

    /// 搜索单曲
    /// keywords: 关键词
    /// offset: 起始点
    /// limit: 数量
    #[allow(unused)]
    pub async fn search_song(
        &self,
        keywords: String,
        offset: u16,
        limit: u16,
    ) -> Result<Vec<SongInfo>> {
        let result = self.search(keywords, 1, offset, limit).await?;
        to_song_info(result, Parse::Search)
    }

    /// 搜索歌手
    /// keywords: 关键词
    /// offset: 起始点
    /// limit: 数量
    #[allow(unused)]
    pub async fn search_singer(
        &self,
        keywords: String,
        offset: u16,
        limit: u16,
    ) -> Result<Vec<SingerInfo>> {
        let result = self.search(keywords, 100, offset, limit).await?;
        to_singer_info(result)
    }

    /// 搜索专辑
    /// keywords: 关键词
    /// offset: 起始点
    /// limit: 数量
    #[allow(unused)]
    pub async fn search_album(
        &self,
        keywords: String,
        offset: u16,
        limit: u16,
    ) -> Result<Vec<SongList>> {
        let result = self.search(keywords, 10, offset, limit).await?;
        to_song_list(result, Parse::SearchAlbum)
    }

    /// 搜索歌单
    /// keywords: 关键词
    /// offset: 起始点
    /// limit: 数量
    #[allow(unused)]
    pub async fn search_songlist(
        &self,
        keywords: String,
        offset: u16,
        limit: u16,
    ) -> Result<Vec<SongList>> {
        let result = self.search(keywords, 1000, offset, limit).await?;
        to_song_list(result, Parse::Search)
    }

    /// 搜索歌词
    /// keywords: 关键词
    /// offset: 起始点
    /// limit: 数量
    #[allow(unused)]
    pub async fn search_lyrics(
        &self,
        keywords: String,
        offset: u16,
        limit: u16,
    ) -> Result<Vec<SongInfo>> {
        let result = self.search(keywords, 1006, offset, limit).await?;
        to_song_info(result, Parse::Search)
    }

    /// 获取歌手热门单曲
    /// id: 歌手 ID
    #[allow(unused)]
    pub async fn singer_songs(&self, id: u64) -> Result<Vec<SongInfo>> {
        let path = format!("/weapi/v1/artist/{}", id);
        let mut params = HashMap::new();
        let result = self
            .request(Method::Post, &path, params, CryptoApi::Weapi, "", false)
            .await?;
        to_song_info(result, Parse::Singer)
    }

    /// 获取歌手全部单曲
    /// id: 歌手 ID
    /// order: 排序方式:
    //	      "hot": 热门
    ///       "time": 时间
    /// offset: 起始点
    /// limit: 数量
    #[allow(unused)]
    pub async fn singer_all_songs(
        &self,
        id: u64,
        order: &str,
        offset: u16,
        limit: u16,
    ) -> Result<Vec<SongInfo>> {
        let path = "/weapi/v1/artist/songs";
        let mut params = HashMap::new();
        let id = id.to_string();
        let offset = offset.to_string();
        let limit = limit.to_string();
        params.insert("id", &id[..]);
        params.insert("private_cloud", "true");
        params.insert("work_type", "1");
        params.insert("order", order);
        params.insert("offset", &offset[..]);
        params.insert("limit", &limit[..]);
        let result = self
            .request(Method::Post, path, params, CryptoApi::Weapi, "", false)
            .await?;
        to_song_info(result, Parse::SingerSongs)
    }

    /// 全部新碟
    /// offset: 起始点
    /// limit: 数量
    /// area: ALL:全部,ZH:华语,EA:欧美,KR:韩国,JP:日本
    #[allow(unused)]
    pub async fn new_albums(&self, area: &str, offset: u16, limit: u16) -> Result<Vec<SongList>> {
        let path = "/weapi/album/new";
        let mut params = HashMap::new();
        let offset = offset.to_string();
        let limit = limit.to_string();
        params.insert("area", area);
        params.insert("offset", &offset[..]);
        params.insert("limit", &limit[..]);
        params.insert("total", "true");
        let result = self
            .request(Method::Post, path, params, CryptoApi::Weapi, "", true)
            .await?;
        to_song_list(result, Parse::Album)
    }

    /// 专辑
    /// album_id: 专辑 id
    #[allow(unused)]
    pub async fn album(&self, album_id: u64) -> Result<AlbumDetail> {
        let path = format!("/weapi/v1/album/{}", album_id);
        let result = self
            .request(
                Method::Post,
                &path,
                HashMap::new(),
                CryptoApi::Weapi,
                "",
                true,
            )
            .await?;
        to_album_detail(&serde_json::from_str(&result)?)
    }

    /// 歌单动态信息
    /// songlist_id: 歌单 id
    #[allow(unused)]
    pub async fn songlist_detail_dynamic(&self, songlist_id: u64) -> Result<PlayListDetailDynamic> {
        let path = "/weapi/playlist/detail/dynamic";
        let mut params = HashMap::new();
        let id = songlist_id.to_string();
        params.insert("id", &id[..]);
        let result = self
            .request(Method::Post, path, params, CryptoApi::Weapi, "", true)
            .await?;
        to_songlist_detail_dynamic(result)
    }

    /// 专辑动态信息
    /// album_id: 专辑 id
    #[allow(unused)]
    pub async fn album_detail_dynamic(&self, album_id: u64) -> Result<AlbumDetailDynamic> {
        let path = "/weapi/album/detail/dynamic";
        let mut params = HashMap::new();
        let id = album_id.to_string();
        params.insert("id", &id[..]);
        let result = self
            .request(Method::Post, path, params, CryptoApi::Weapi, "", true)
            .await?;
        to_album_detail_dynamic(result)
    }

    /// 热门推荐歌单
    /// offset: 起始点
    /// limit: 数量
    /// order: 排序方式:
    //	      "hot": 热门，
    ///       "new": 最新
    /// cat: 全部,华语,欧美,日语,韩语,粤语,小语种,流行,摇滚,民谣,电子,舞曲,说唱,轻音乐,爵士,乡村,R&B/Soul,古典,民族,英伦,金属,朋克,蓝调,雷鬼,世界音乐,拉丁,另类/独立,New Age,古风,后摇,Bossa Nova,清晨,夜晚,学习,工作,午休,下午茶,地铁,驾车,运动,旅行,散步,酒吧,怀旧,清新,浪漫,性感,伤感,治愈,放松,孤独,感动,兴奋,快乐,安静,思念,影视原声,ACG,儿童,校园,游戏,70后,80后,90后,网络歌曲,KTV,经典,翻唱,吉他,钢琴,器乐,榜单,00后
    #[allow(unused)]
    pub async fn top_song_list(
        &self,
        cat: &str,
        order: &str,
        offset: u16,
        limit: u16,
    ) -> Result<Vec<SongList>> {
        let path = "/weapi/playlist/list";
        let mut params = HashMap::new();
        let offset = offset.to_string();
        let limit = limit.to_string();
        params.insert("cat", cat);
        params.insert("order", order);
        params.insert("total", "true");
        params.insert("offset", &offset[..]);
        params.insert("limit", &limit[..]);
        let result = self
            .request(Method::Post, path, params, CryptoApi::Weapi, "", true)
            .await?;
        to_song_list(result, Parse::Top)
    }

    /// 精品歌单
    /// lasttime: 分页参数,取上一页最后一个歌单的 updateTime 获取下一页数据
    /// limit: 数量
    /// cat: 全部,华语,欧美,韩语,日语,粤语,小语种,运动,ACG,影视原声,流行,摇滚,后摇,古风,民谣,轻音乐,电子,器乐,说唱,古典,爵士
    #[allow(unused)]
    pub async fn top_song_list_highquality(
        &self,
        cat: &str,
        lasttime: u8,
        limit: u8,
    ) -> Result<Vec<SongList>> {
        let path = "/api/playlist/highquality/list";
        let mut params = HashMap::new();
        let lasttime = lasttime.to_string();
        let limit = limit.to_string();
        params.insert("cat", cat);
        params.insert("total", "true");
        params.insert("lasttime", &lasttime[..]);
        params.insert("limit", &limit[..]);
        let result = self
            .request(Method::Post, path, params, CryptoApi::Weapi, "", true)
            .await?;
        to_song_list(result, Parse::Top)
    }

    /// 获取排行榜
    #[allow(unused)]
    pub async fn toplist(&self) -> Result<Vec<TopList>> {
        let path = "/api/toplist";
        let mut params = HashMap::new();
        let res = self
            .request(Method::Post, path, params, CryptoApi::Weapi, "", true)
            .await?;
        to_toplist(res)
    }

    /// 热门歌曲/排行榜
    /// list_id:
    /// 云音乐飙升榜: 19723756
    /// 云音乐新歌榜: 3779629
    /// 网易原创歌曲榜: 2884035
    /// 云音乐热歌榜: 3778678
    /// 云音乐古典音乐榜: 71384707
    /// 云音乐ACG音乐榜: 71385702
    /// 云音乐韩语榜: 745956260
    /// 云音乐国电榜: 10520166
    /// 云音乐嘻哈榜: 991319590']
    /// 抖音排行榜: 2250011882
    /// UK排行榜周榜: 180106
    /// 美国Billboard周榜: 60198
    /// KTV嗨榜: 21845217
    /// iTunes榜: 11641012
    /// Hit FM Top榜: 120001
    /// 日本Oricon周榜: 60131
    /// 台湾Hito排行榜: 112463
    /// 香港电台中文歌曲龙虎榜: 10169002
    /// 华语金曲榜: 4395559
    #[allow(unused)]
    pub async fn top_songs(&self, list_id: u64) -> Result<PlayListDetail> {
        self.song_list_detail(list_id).await
    }

    /// 查询歌词
    /// music_id: 歌曲id
    #[allow(unused)]
    pub async fn song_lyric(&self, music_id: u64) -> Result<Lyrics> {
        let empty = String::new();
        let csrf_token = self.csrf.get().unwrap_or(&empty);
        let path = "/weapi/song/lyric";
        let mut params = HashMap::new();
        let id = music_id.to_string();
        params.insert("id", &id[..]);
        params.insert("lv", "-1");
        params.insert("tv", "-1");
        params.insert("csrf_token", csrf_token);
        let result = self
            .request(Method::Post, path, params, CryptoApi::Weapi, "", true)
            .await?;
        to_lyric(result)
    }

    /// 收藏/取消收藏歌单
    /// like: true 收藏，false 取消
    /// id: 歌单 id
    #[allow(unused)]
    pub async fn song_list_like(&self, like: bool, id: u64) -> bool {
        let path = if like {
            "/weapi/playlist/subscribe"
        } else {
            "/weapi/playlist/unsubscribe"
        };
        let mut params = HashMap::new();
        let id = id.to_string();
        params.insert("id", &id[..]);
        if let Ok(result) = self
            .request(Method::Post, path, params, CryptoApi::Weapi, "", true)
            .await
        {
            return to_msg(result)
                .unwrap_or(Msg {
                    code: 0,
                    msg: "".to_owned(),
                })
                .code
                .eq(&200);
        }
        false
    }

    /// 收藏/取消收藏专辑
    /// like: true 收藏，false 取消
    /// id: 歌单 id
    #[allow(unused)]
    pub async fn album_like(&self, like: bool, id: u64) -> bool {
        let path = if like {
            "/api/album/sub"
        } else {
            "/api/album/unsub"
        };
        let path = format!("{}?id={}", path, id);
        let mut params = HashMap::new();
        let id = id.to_string();
        params.insert("id", id.as_str());
        if let Ok(result) = self
            .request(Method::Post, &path, params, CryptoApi::Weapi, "", false)
            .await
        {
            return to_msg(result)
                .unwrap_or(Msg {
                    code: 0,
                    msg: "".to_owned(),
                })
                .code
                .eq(&200);
        }
        false
    }

    /// 获取 APP 首页信息
    #[allow(unused)]
    pub async fn homepage(&self, client_type: ClientType) -> Result<String> {
        let path = "/api/homepage/block/page";
        let mut params = HashMap::new();
        params.insert("refresh", "false");
        params.insert("cursor", "null");
        self.request(Method::Post, path, params, CryptoApi::Weapi, "", true)
            .await
    }

    /// 获取首页轮播图
    #[allow(unused)]
    pub async fn banners(&self) -> Result<Vec<BannersInfo>> {
        let path = "/weapi/v2/banner/get";
        let mut params = HashMap::new();
        params.insert("clientType", "pc");
        let result = self
            .request(Method::Post, path, params, CryptoApi::Weapi, "", true)
            .await?;
        to_banners_info(result)
    }

    /// 用户电台定阅列表
    /// offset: 列表起点号
    /// limit: 列表长度
    #[allow(unused)]
    pub async fn user_radio_sublist(&self, offset: u16, limit: u16) -> Result<Vec<SongList>> {
        let path = "/weapi/djradio/get/subed";
        let mut params = HashMap::new();
        let offset = offset.to_string();
        let limit = limit.to_string();
        params.insert("total", "true");
        params.insert("offset", offset.as_str());
        params.insert("limit", limit.as_str());
        let result = self
            .request(Method::Post, path, params, CryptoApi::Weapi, "", true)
            .await?;
        to_song_list(result, Parse::Radio)
    }

    /// 电台节目列表
    /// rid: 电台ID
    /// offset: 列表起点号
    /// limit: 列表长度
    #[allow(unused)]
    pub async fn radio_program(&self, rid: u64, offset: u16, limit: u16) -> Result<Vec<SongInfo>> {
        let path = "/weapi/dj/program/byradio";
        let mut params = HashMap::new();
        let id = rid.to_string();
        let offset = offset.to_string();
        let limit = limit.to_string();
        params.insert("radioId", id.as_str());
        params.insert("offset", offset.as_str());
        params.insert("limit", limit.as_str());
        params.insert("asc", "false");
        let result = self
            .request(Method::Post, path, params, CryptoApi::Weapi, "", true)
            .await?;
        to_song_info(result, Parse::Radio)
    }

    /// 心动模式/智能播放
    /// song_id: 歌曲ID
    /// playlist_id: 歌单ID
    #[allow(unused)]
    pub async fn playmode_intelligence_list(&self, sid: u64, pid: u64) -> Result<Vec<SongInfo>> {
        let path = "/weapi/playmode/intelligence/list";
        let mut params = HashMap::new();
        let id = sid.to_string();
        let pid = pid.to_string();
        params.insert("songId", id.as_str());
        params.insert("type", "fromPlayOne");
        params.insert("playlistId", pid.as_str());
        params.insert("startMusicId", id.as_str());
        params.insert("count", "1");
        let result = self
            .request(Method::Post, path, params, CryptoApi::Weapi, "", true)
            .await?;
        to_song_info(result, Parse::Intelligence)
    }
}

fn choose_user_agent(ua: &str) -> &str {
    let index = if ua == "mobile" {
        rand::random::<u16>() % 7
    } else if ua == "pc" {
        rand::random::<u16>() % 5 + 8
    } else if !ua.is_empty() {
        return ua;
    } else {
        rand::random::<u16>() % USER_AGENT_LIST.len() as u16
    };
    USER_AGENT_LIST[index as usize]
}

fn generate_request_id() -> String {
    let now = Utc::now().timestamp_millis();
    let random_num: u32 = rand::random_range(0..1000);

    format!("{}_{:04}", now, random_num)
}

#[cfg(test)]
mod tests {

    use super::*;

    #[tokio::test]
    async fn test() {
        let ctcode = "";
        let phone = "";
        let mut api = MusicApi::default();
        if let Ok(file) = std::fs::File::open("cookies.json").map(std::io::BufReader::new) {
            api = MusicApi::from_cookie_jar(cookie_store::serde::json::load(file).unwrap(), 0);
        } else {
            let _ = api.captcha(ctcode.to_string(), phone.to_string()).await;
            let mut input = String::new();
            std::io::stdin().read_line(&mut input).unwrap();

            let _ = api
                .login_cellphone(
                    ctcode.to_string(),
                    phone.to_string(),
                    input.trim().to_string(),
                )
                .await;
        }
        // test code
        println!("{:?}", api.login_status().await);
        println!("{:?}", api.songs_url(&[29444040], "lossless").await);
        // test code
        {
            let mut writer = std::fs::File::create("cookies.json")
                .map(std::io::BufWriter::new)
                .unwrap();
            let cookie_jar = api.cookie_jar();
            let store = cookie_jar.lock().unwrap();
            cookie_store::serde::json::save(&store, &mut writer).unwrap();
        }
        assert!(true);
    }
}
