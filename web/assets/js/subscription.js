(function () {
  // Vue app for Subscription page
  const el = document.getElementById('subscription-data');
  if (!el) return;
  const textarea = document.getElementById('subscription-links');
  const rawLinks = (textarea?.value || '').split('\n').filter(Boolean);
  // Username/password VPNs are emitted as compatibility trojan:// records so
  // subscription clients retain quota visibility. They are not real proxy links:
  // render them as readable connection cards and keep them out of the raw URI list.
  function parseConnectionCard(link) {
    if (!link || !link.startsWith('trojan://') || !link.includes('#')) return null;
    try {
      const parsed = new URL(link);
      const fragment = decodeURIComponent(parsed.hash.slice(1));
      const match = fragment.match(/\\b(OpenVPN|L2TP\\/IPsec|PPTP|OpenConnect|SSTP|IKEv2)\\b/i);
      if (!match) return null;
      const upper = match[1].toUpperCase();
      const protocol = upper === 'OPENVPN' ? 'OpenVPN' :
        upper === 'L2TP/IPSEC' ? 'L2TP/IPsec' :
        upper === 'IKEV2' ? 'IKEv2' : match[1][0].toUpperCase() + match[1].slice(1);
      const read = key => {
        const found = fragment.match(new RegExp('(?:^|\\\\s)' + key + '=([^\\\\s]*)'));
        return found ? found[1] : '';
      };
      const fields = [
        { key: 'server', label: 'Server address', value: parsed.hostname },
        { key: 'port', label: 'Port', value: parsed.port || '—' },
        { key: 'user', label: 'Username', value: read('user') },
        { key: 'pass', label: 'Password', value: read('pass') }
      ];
      const psk = read('psk');
      if (psk) fields.push({ key: 'psk', label: 'IPsec pre-shared key (PSK)', value: psk });
      return { protocol, fields: fields.filter(field => field.value) };
    } catch (e) {
      return null;
    }
  }
  const connectionCards = rawLinks.map(parseConnectionCard).filter(Boolean);
  const visibleLinks = rawLinks.filter(link => !parseConnectionCard(link));


  const data = {
    sId: el.getAttribute('data-sid') || '',
    subUrl: el.getAttribute('data-sub-url') || '',
    subJsonUrl: el.getAttribute('data-subjson-url') || '',
    subClashUrl: el.getAttribute('data-subclash-url') || '',
    download: el.getAttribute('data-download') || '',
    upload: el.getAttribute('data-upload') || '',
    used: el.getAttribute('data-used') || '',
    total: el.getAttribute('data-total') || '',
    remained: el.getAttribute('data-remained') || '',
    expireMs: (parseInt(el.getAttribute('data-expire') || '0', 10) || 0) * 1000,
    lastOnlineMs: (parseInt(el.getAttribute('data-lastonline') || '0', 10) || 0),
    downloadByte: parseInt(el.getAttribute('data-downloadbyte') || '0', 10) || 0,
    uploadByte: parseInt(el.getAttribute('data-uploadbyte') || '0', 10) || 0,
    totalByte: parseInt(el.getAttribute('data-totalbyte') || '0', 10) || 0,
    datepicker: el.getAttribute('data-datepicker') || 'gregorian',
  };

  // Normalize lastOnline to milliseconds if it looks like seconds
  if (data.lastOnlineMs && data.lastOnlineMs < 10_000_000_000) {
    data.lastOnlineMs *= 1000;
  }

  function renderLink(item) {
    return (
      Vue.h('a-list-item', {}, [
        Vue.h('a-space', { props: { size: 'small' } }, [
          Vue.h('a-button', { props: { size: 'small' }, on: { click: () => copy(item) } }, [Vue.h('a-icon', { props: { type: 'copy' } })]),
          Vue.h('span', { class: 'break-all' }, item)
        ])
      ])
    );
  }

  function copy(text) {
    ClipboardManager.copyText(text).then(ok => {
      const messageType = ok ? 'success' : 'error';
      Vue.prototype.$message[messageType](ok ? 'Copied' : 'Copy failed');
    });
  }

  function open(url) {
    window.location.href = url;
  }

  function drawQR(value) {
    try {
      new QRious({ element: document.getElementById('qrcode'), value, size: 220 });
    } catch (e) {
      console.warn(e);
    }
  }

  // Try to extract a human label (email/ps) from different link types
  function linkName(link, idx) {
    try {
      if (link.startsWith('vmess://')) {
        const json = JSON.parse(atob(link.replace('vmess://', '')));
        if (json.ps) return json.ps;
        if (json.add && json.id) return json.add; // fallback host
      } else if (link.startsWith('vless://') || link.startsWith('trojan://')) {
        const hashIdx = link.indexOf('#');
        if (hashIdx !== -1) return decodeURIComponent(link.substring(hashIdx + 1));
        const qIdx = link.indexOf('?');
        if (qIdx !== -1) {
          const qs = new URL('http://x/?' + link.substring(qIdx + 1, hashIdx !== -1 ? hashIdx : undefined)).searchParams;
          if (qs.get('remark')) return qs.get('remark');
          if (qs.get('email')) return qs.get('email');
        }
        const at = link.indexOf('@');
        const protSep = link.indexOf('://');
        if (at !== -1 && protSep !== -1) return link.substring(protSep + 3, at);
      } else if (link.startsWith('ss://')) {
        const hashIdx = link.indexOf('#');
        if (hashIdx !== -1) return decodeURIComponent(link.substring(hashIdx + 1));
      } else if (link.startsWith('tg://')) {
        // tg://proxy?server=HOST&port=..&secret=.. -> label with the server host.
        const qs = new URL('http://x/?' + link.substring(link.indexOf('?') + 1)).searchParams;
        const host = qs.get('server');
        return host ? 'MTProto (' + host + ')' : 'MTProto';
      } else if (link.startsWith('ssh://')) {
        // ssh://base64(user:pass@host:port)[#label] -> prefer the #label, else the host.
        const hashIdx = link.indexOf('#');
        if (hashIdx !== -1) return decodeURIComponent(link.substring(hashIdx + 1));
        const decoded = atob(link.substring('ssh://'.length));
        const at = decoded.lastIndexOf('@');
        return 'SSH' + (at !== -1 ? ' (' + decoded.substring(at + 1) + ')' : '');
      } else if (link.startsWith('wireguard://')) {
        // wg-c/awg: wireguard://<privkey>@host:port?..#remark -> the remark names the
        // device; fall back to the endpoint so a link without one still reads.
        const hashIdx = link.indexOf('#');
        if (hashIdx !== -1) return decodeURIComponent(link.substring(hashIdx + 1));
        const at = link.indexOf('@');
        const qIdx = link.indexOf('?');
        return at !== -1 ? 'WireGuard (' + link.substring(at + 1, qIdx === -1 ? undefined : qIdx) + ')'
                         : 'WireGuard';
      }
    } catch (e) { /* ignore and fallback */ }
    return 'Link ' + (idx + 1);
  }

  const app = new Vue({
    delimiters: ['[[', ']]'],
    el: '#app',
    data: {
      themeSwitcher,
      app: data,
      links: visibleLinks,
      connectionCards,
      lang: '',
      viewportWidth: (typeof window !== 'undefined' ? window.innerWidth : 1024),
    },
    async mounted() {
      this.lang = LanguageManager.getLanguage();
      const tpl = document.getElementById('subscription-data');
      const sj = tpl ? tpl.getAttribute('data-subjson-url') : '';
      const sc = tpl ? tpl.getAttribute('data-subclash-url') : '';
      if (sj) this.app.subJsonUrl = sj;
      if (sc) this.app.subClashUrl = sc;
      drawQR(this.app.subUrl);
      try {
        const elJson = document.getElementById('qrcode-subjson');
        if (elJson && this.app.subJsonUrl) {
          new QRious({ element: elJson, value: this.app.subJsonUrl, size: 220 });
        }
        const elClash = document.getElementById('qrcode-subclash');
        if (elClash && this.app.subClashUrl) {
          new QRious({ element: elClash, value: this.app.subClashUrl, size: 220 });
        }
      } catch (e) { /* ignore */ }
      this._onResize = () => { this.viewportWidth = window.innerWidth; };
      window.addEventListener('resize', this._onResize);
    },
    beforeDestroy() {
      if (this._onResize) window.removeEventListener('resize', this._onResize);
    },
    computed: {
      isMobile() {
        return this.viewportWidth < 576;
      },
      isUnlimited() {
        return !this.app.totalByte;
      },
      isActive() {
        const now = Date.now();
        const expiryOk = !this.app.expireMs || this.app.expireMs >= now;
        const trafficOk = !this.app.totalByte || (this.app.uploadByte + this.app.downloadByte) <= this.app.totalByte;
        return expiryOk && trafficOk;
      },
      shadowrocketUrl() {
        const rawUrl = this.app.subUrl + '?flag=shadowrocket';
        const base64Url = btoa(rawUrl);
        const remark = encodeURIComponent(this.app.sId || 'Subscription');
        return `shadowrocket://add/sub/${base64Url}?remark=${remark}`;
      },
      v2boxUrl() {
        return `v2box://install-sub?url=${encodeURIComponent(this.app.subUrl)}&name=${encodeURIComponent(this.app.sId)}`;
      },
      streisandUrl() {
        return `streisand://import/${encodeURIComponent(this.app.subUrl)}`;
      },
      v2raytunUrl() {
        return this.app.subUrl;
      },
      npvtunUrl() {
        return this.app.subUrl;
      },
      happUrl() {
        return `happ://add/${this.app.subUrl}`;
      }
    },
    methods: {
      renderLink,
      copy,
      open,
      linkName,
      i18nLabel(key) {
        return '{{ i18n "' + key + '" }}';
      },
    },
  });
})();
