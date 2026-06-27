必须重新生成的两样(安全)

  1. internal_secret — 必须换新。
  你贴的这串 256b6d81... 是我在开发期生成、并且在我们对话里明文出现过、还写进了开发机的 config.yaml。它已经不算秘密了。生产环境务必重新生成:
  openssl rand -hex 32
  把新值填进生产 config.yaml,同一个值也要配到 image-studio 那边(它调 /internal/cred 时要带这个 X-Internal-Secret)。两边必须一致。

  2. jwt_private_key_file 指向的私钥 —— 必须重新生成一对。
  开发机那个 backend/data/image_studio_private.pem 同理不能用于生产(它在开发环境待过)。生产环境重新生成一对:
  openssl genrsa -out data/image_studio_private.pem 2048
  openssl rsa -in data/image_studio_private.pem -pubout -out image_studio_public.pem
  chmod 600 data/image_studio_private.pem
  关键:导出的公钥 image_studio_public.pem 必须交给 image-studio——它用公钥验签你签发的票据。私钥留母系统、公钥给 image-studio,这是整个信任模型的根。私钥换了,公钥也得跟着重新下发给
  image-studio。

  另外,jwt_private_key_file: "data/.." 是相对后端工作目录的路径,确认生产环境后端的 CWD 下这个相对路径能解析到文件(否则用绝对路径)。

  取决于拓扑的一样

  gateway_base_url —— 看 image-studio 后端能否够到母系统。
  这个地址是 image-studio 后端进程(不是浏览器)用来 server-to-server 调你网关 /v1/images/generations 的。判断标准只有一条:image-studio 那个进程能不能访问到这个地址。

  - image-studio 和 sub2api 同机/同容器 → http://localhost:[生产内网监听端口]/v1 ✅ 可以,且最优(省一次公网 TLS 往返,不绕 nginx)。
  - 两者在同一 Docker 网络但不同容器 → localhost 够不到,要用 http://[sub2api容器名或内网IP]:[端口]/v1。
  - 两者完全分离、只能走公网 → 才用公网地址 https://你的域名/v1。

  不需要因为"生产"就改成公网——能内网直连就内网,公网只是够不到时的退路。

  必须在管理后台做的一项

  功能开关本身(image_studio.enabled)是配置项,管理后台没有对应开关,不用在后台动它。

  但有一个部署前提必须在管理后台落实(否则用户进去出不了图):至少有一个分组满足三个条件——
  1. 平台 = OpenAI
  2. allow_image_generation = true(后台分组编辑里那个"允许图片生成"开关)
  3. 该分组的账号映射把 gpt-image-* 映射到真实可出图的上游模型

  这正是我们测试时让你手动开的那个开关。生产环境你得确保面向目标用户的那个 OpenAI 分组,这三项都配好了。否则候选列表为空、can_create=false,用户只会看到"没有可用的绘图分组,请联系客服"。

  还要顺带确认的(非 config.yaml,属部署)

  - jwt_issuer / jwt_audience:你填的 sub2api / image-studio 必须和 image-studio 验签时校验的字面值完全一致,否则验签失败。两边对齐即可。
  - image_model:gpt-image-2 要和上面那个分组的账号映射的源模型名对得上。
  - nginx:配 location /image-studio/(排兜底前、SE 关 proxy_buffering),并且确保 /internal/ 不被公网暴露(不给它配 location或显式 deny)——否则拿到 internal_secret 就能查任意用户的 key。

  ---
  一句话总结:enabled / jwt_issuer / jwt_audience / ticket_ttl_seconds / image_model 可以照抄;internal_secret 和私钥文件必须在生产重新生成(并把新公钥+新 secret 同步给
  image-studio);gateway_base_url 按 image-studio 能否内网够到母系统来定;管理后台不开功能开关,但必须备好一个合规的 OpenAI 作图分组。