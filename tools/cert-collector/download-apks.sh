#!/bin/bash
# Download APKs from APKPure — Chinese fintech + global payment apps
# For academic research dataset expansion (123 → 500 certs)

set -e
DOWNLOAD_DIR="${1:-/tmp/apk-dataset}"
mkdir -p "$DOWNLOAD_DIR"

echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║  APK Dataset Downloader — Top Finance/Payment Apps           ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""
echo "Download directory: $DOWNLOAD_DIR"
echo ""

# Chinese fintech apps (top 100)
APPS=(
  # Payment & Banking
  "com.eg.android.AlipayGphone"        # Alipay
  "com.tencent.mm"                     # WeChat
  "com.unionpay"                       # UnionPay
  "com.chinamworld.main"               # China Construction Bank
  "com.icbc"                           # ICBC
  "com.chinamworld.bocmbci"            # Bank of China
  "com.abchina.cashier"               # Agricultural Bank
  "cmb.pb"                            # China Merchants Bank
  "com.pingan.paces.ccms"             # Ping An
  "com.cib.cibmb"                     # Industrial Bank
  # E-commerce
  "com.jingdong.app.mall"              # JD.com
  "com.taobao.taobao"                  # Taobao
  "com.xunmeng.pinduoduo"             # Pinduoduo
  "com.meituan"                        # Meituan
  "com.sankuai.meituan.takeoutnew"    # Meituan Waimai
  # Crypto
  "com.binance.dev"                    # Binance
  "com.okinc.okex.gp"                 # OKX
  "vip.mytokenpocket"                  # TokenPocket
  "im.token.app"                       # imToken
  "com.wallet.crypto.trustapp"         # Trust Wallet
  # Global payment
  "com.google.android.apps.nbu.paisa.user" # Google Pay
  "com.paypal.android.p2pmobile"       # PayPal
  "com.squareup.cash"                  # Cash App
  "com.venmo"                          # Venmo
  "com.stripe.android.dashboard"       # Stripe
  # SE Asian fintech
  "com.grab.merchant"                  # Grab
  "xyz.seagroup.shopee"               # Shopee
  "com.gojek.app"                     # Gojek
  "com.bk.dana"                       # DANA
  "id.co.ovo.cash"                    # OVO
  # Global banking
  "com.chase.sig.android"             # Chase
  "com.wf.wellsfargomobile"           # Wells Fargo
  "com.infonow.bofa"                  # Bank of America
  "com.citi.citimobile"               # Citi
  "com.hsbc.hsbcnet"                  # HSBC
  "com.db.pbc.mibankapp.nz"          # Deutsche Bank
  "com.barclays.android.barclaysmobilebanking" # Barclays
  "sg.com.dbs.dbsmbanking"           # DBS
  "com.ocbc.mobile"                   # OCBC
  "com.uob.mighty"                    # UOB
  # Insurance & Investment
  "com.robinhood.android"             # Robinhood
  "com.coinbase.android"              # Coinbase
  "com.revolut.revolut"               # Revolut
  "com.N26"                           # N26
  "com.wise.android"                  # Wise
  # Chinese lifestyle (with payment)
  "com.dianping.v1"                   # Dianping
  "com.autonavi.minimap"              # Amap
  "com.sdu.didi.gsui"                 # Didi
  "ctrip.android.view"               # Ctrip
  "com.Qunar"                         # Qunar
)

echo "Target apps: ${#APPS[@]}"
echo ""

DOWNLOADED=0
for pkg in "${APPS[@]}"; do
  OUTPUT="$DOWNLOAD_DIR/${pkg}.apk"
  if [ -f "$OUTPUT" ]; then
    echo "  SKIP (exists): $pkg"
    continue
  fi

  echo -n "  Downloading: $pkg... "

  # Try APKPure direct download
  URL="https://d.apkpure.com/b/APK/${pkg}?version=latest"
  HTTP_CODE=$(curl -sL -o "$OUTPUT" -w "%{http_code}" \
    -H "User-Agent: Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36" \
    --max-time 60 "$URL" 2>/dev/null)

  if [ "$HTTP_CODE" = "200" ] && [ -s "$OUTPUT" ]; then
    SIZE=$(wc -c < "$OUTPUT" | tr -d ' ')
    if [ "$SIZE" -gt 10000 ]; then
      echo "OK (${SIZE} bytes)"
      DOWNLOADED=$((DOWNLOADED + 1))
    else
      echo "FAIL (too small: ${SIZE})"
      rm -f "$OUTPUT"
    fi
  else
    echo "FAIL (HTTP $HTTP_CODE)"
    rm -f "$OUTPUT"
  fi

  # Rate limit
  sleep 2
done

echo ""
echo "━━━ Download Summary ━━━"
echo "  Downloaded: $DOWNLOADED / ${#APPS[@]}"
echo "  Directory: $DOWNLOAD_DIR"
echo ""
echo "Next step: Run cert collector:"
echo "  python3 tools/cert-collector/collect-certs.py $DOWNLOAD_DIR"
