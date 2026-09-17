/** Soft notification tones via Web Audio — no external files. */
const AegisSound = (() => {
  let ctx = null;
  let enabled = true;
  try {
    enabled = localStorage.getItem("aegis_sound") !== "0";
  } catch {
    /* ignore */
  }

  function ac() {
    if (!ctx) {
      const Ctx = window.AudioContext || window.webkitAudioContext;
      if (!Ctx) return null;
      ctx = new Ctx();
    }
    if (ctx.state === "suspended") ctx.resume().catch(() => {});
    return ctx;
  }

  function tone(freq, start, dur, gain = 0.045, type = "sine") {
    const c = ac();
    if (!c) return;
    const osc = c.createOscillator();
    const g = c.createGain();
    osc.type = type;
    osc.frequency.value = freq;
    g.gain.setValueAtTime(0.0001, start);
    g.gain.exponentialRampToValueAtTime(gain, start + 0.02);
    g.gain.exponentialRampToValueAtTime(0.0001, start + dur);
    osc.connect(g);
    g.connect(c.destination);
    osc.start(start);
    osc.stop(start + dur + 0.02);
  }

  function play(kind) {
    if (!enabled) return;
    const c = ac();
    if (!c) return;
    const t = c.currentTime + 0.01;
    if (kind === "allow") {
      // soft ascending two-note
      tone(660, t, 0.12, 0.04);
      tone(880, t + 0.08, 0.16, 0.04);
    } else if (kind === "review") {
      // attention: mid pulse
      tone(520, t, 0.14, 0.05);
      tone(520, t + 0.18, 0.14, 0.04);
    } else if (kind === "block") {
      // alert: lower double
      tone(320, t, 0.16, 0.055, "triangle");
      tone(260, t + 0.14, 0.2, 0.055, "triangle");
    } else {
      tone(600, t, 0.1, 0.035);
    }
  }

  function setEnabled(v) {
    enabled = Boolean(v);
    try {
      localStorage.setItem("aegis_sound", enabled ? "1" : "0");
    } catch {
      /* ignore */
    }
    return enabled;
  }

  function isEnabled() {
    return enabled;
  }

  return { play, setEnabled, isEnabled };
})();

window.AegisSound = AegisSound;
