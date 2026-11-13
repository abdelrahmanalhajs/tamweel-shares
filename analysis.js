/* Tamweel Shares — financial analysis engine.
   Pure functions, shared by the Node server and the browser (UMD). All amounts in dollars.
   Everything here is rule-based and explainable: no black-box scoring, and nothing is a guarantee. */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.TWAnalysis = factory();
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';
  const num = v => (Number.isFinite(+v) ? +v : 0);
  const sum = (a, f) => a.reduce((x, r) => x + f(r), 0);
  const clamp = (v, lo, hi) => Math.max(lo, Math.min(hi, v));
  const median = a => { const s = a.slice().sort((x, y) => x - y), m = s.length >> 1; return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2; };
  const FIELDS = ['revenue', 'cogs', 'direct', 'indirect', 'payroll', 'rent', 'utilities', 'commissions', 'marketing', 'other', 'debtPayments', 'liabilities'];

  const expenses = r => num(r.cogs) + num(r.direct) + num(r.indirect) + num(r.payroll) + num(r.rent) + num(r.utilities) + num(r.commissions) + num(r.marketing) + num(r.other);

  /* rows: monthly statements. ctx: { declaredSales, declaredProfit, foundedYear, docKinds, year } */
  function analyze(rowsIn, ctx = {}) {
    const rows = rowsIn.map(r => ({ ...r })).sort((a, b) => (a.month < b.month ? -1 : 1));
    const n = rows.length;
    const series = rows.map(r => {
      const exp = expenses(r), profit = num(r.revenue) - exp;
      return { month: r.month, revenue: num(r.revenue), expenses: exp, profit, cash: profit - num(r.debtPayments), verified: !!r.verified };
    });
    if (!n) return { n: 0, series, metrics: null, flags: [{ code: 'no_data' }], rating: null };

    const totRev = sum(series, r => r.revenue), totExp = sum(series, r => r.expenses), totProfit = totRev - totExp;
    const avgRev = totRev / n, avgExp = totExp / n, avgProfit = totProfit / n;
    const avgCash = sum(series, r => r.cash) / n;
    const cogs = sum(rows, r => num(r.cogs)), variable = cogs + sum(rows, r => num(r.direct) + num(r.commissions));
    const fixed = (totExp - variable + sum(rows, r => num(r.debtPayments))) / n;
    const contribution = totRev ? 1 - variable / totRev : 0;
    const breakEven = contribution > 0 ? fixed / contribution : null;
    // revenue trend: least-squares slope as % of mean revenue per month
    let growth = 0;
    if (n >= 3 && avgRev > 0) {
      const mx = (n - 1) / 2; let sxy = 0, sxx = 0;
      series.forEach((r, i) => { sxy += (i - mx) * (r.revenue - avgRev); sxx += (i - mx) ** 2; });
      growth = (sxy / sxx) / avgRev * 100;
    }
    const cv = avgRev > 0 ? Math.sqrt(sum(series, r => (r.revenue - avgRev) ** 2) / n) / avgRev : 1;
    const lastLiab = num(rows[n - 1].liabilities);
    const debtRatio = avgRev > 0 ? lastLiab / (avgRev * 12) : null;
    const verifiedShare = sum(series, r => (r.verified ? 1 : 0)) / n;
    const metrics = {
      months: n, avgRevenue: avgRev, avgExpenses: avgExp, avgProfit, avgCash,
      grossMargin: totRev ? (totRev - cogs) / totRev * 100 : null, netMargin: avgRev ? avgProfit / avgRev * 100 : null,
      breakEven, marginOfSafety: breakEven && avgRev ? (avgRev - breakEven) / avgRev * 100 : null,
      growthPerMonth: growth, volatility: cv * 100, liabilities: lastLiab, debtRatio, verifiedShare: verifiedShare * 100,
      totalRevenue: totRev, totalProfit: totProfit
    };

    /* ---- risk / anomaly flags (each is a code + data; the UI translates) ---- */
    const flags = [];
    if (n < 6) flags.push({ code: 'thin_data', months: n });
    const lossMonths = series.filter(r => r.profit < 0).length;
    if (lossMonths) flags.push({ code: 'loss_months', count: lossMonths });
    if (n >= 4) {
      const l = series.slice(-4).map(r => r.revenue);
      if (l[0] > l[1] && l[1] > l[2] && l[2] > l[3]) flags.push({ code: 'sales_decline' });
      const med = median(series.map(r => r.expenses));
      const spikes = series.filter(r => med > 0 && r.expenses > med * 1.3).map(r => r.month);
      if (spikes.length) flags.push({ code: 'expense_spike', months: spikes });
      const ratio = r => (r.revenue ? r.expenses / r.revenue : 0);
      if (ratio(series[n - 1]) > 1 && ratio(series[0]) <= 1) flags.push({ code: 'expenses_exceed_sales' });
    }
    const ds = num(ctx.declaredSales), dp = num(ctx.declaredProfit);
    if (ds > 0 && Math.abs(avgRev - ds) / ds > 0.15) flags.push({ code: 'declared_sales_mismatch', declared: ds, actual: avgRev });
    if (dp > 0 && Math.abs(avgProfit - dp) / dp > 0.25) flags.push({ code: 'declared_profit_mismatch', declared: dp, actual: avgProfit });
    if (debtRatio !== null && debtRatio > 0.5) flags.push({ code: 'high_debt', ratio: debtRatio * 100 });
    if (n >= 3 && num(rows[n - 1].liabilities) > num(rows[n - 2].liabilities) && num(rows[n - 2].liabilities) > num(rows[n - 3].liabilities))
      flags.push({ code: 'debt_growing' });
    if (avgCash < 0) flags.push({ code: 'negative_cash' });
    if (verifiedShare < 0.5) flags.push({ code: 'mostly_unverified', share: verifiedShare * 100 });
    // suspiciously round / identical figures can indicate invented data
    if (n >= 4 && series.every(r => r.revenue === series[0].revenue)) flags.push({ code: 'identical_revenue' });

    /* ---- explainable rating (0-100) ---- */
    let rating = null;
    if (n >= 3) {
      const comp = [];
      const add = (key, max, score, v) => comp.push({ key, max, score: Math.round(clamp(score, 0, max) * 10) / 10, v });
      add('stability', 15, Math.min(n, 12) / 12 * 8 + (cv < 0.15 ? 7 : cv < 0.3 ? 4 : 1), { months: n, volatility: cv * 100 });
      add('profitability', 25, metrics.netMargin > 0 ? metrics.netMargin / 25 * 25 : 0, { margin: metrics.netMargin });
      add('growth', 15, (growth + 2) / 5 * 15, { growth });
      add('cashflow', 15, series.filter(r => r.cash > 0).length / n * 15, { avgCash });
      add('debt', 10, debtRatio === null ? 0 : (1 - debtRatio) * 10, { ratio: debtRatio === null ? null : debtRatio * 100 });
      add('verification', 10, verifiedShare * 6 + Math.min(num(ctx.docKinds), 4) / 4 * 4, { share: verifiedShare * 100, docs: num(ctx.docKinds) });
      const age = ctx.foundedYear ? num(ctx.year || new Date().getFullYear()) - num(ctx.foundedYear) : null;
      add('history', 10, age === null ? 3 : Math.min(Math.max(age, 0), 5) / 5 * 10, { age });
      const score = Math.round(sum(comp, c => c.score));
      rating = { score, grade: score >= 80 ? 'A' : score >= 65 ? 'B' : score >= 50 ? 'C' : 'D',
        suggestedRisk: score >= 75 ? 'low' : score >= 55 ? 'medium' : 'high', components: comp };
    }
    if (n >= 4 && series.every(r => r.revenue > 0 && r.revenue % 1000 === 0)) flags.push({ code: 'round_numbers' });
    if (n >= 4 && series.every(r => r.expenses === series[0].expenses)) flags.push({ code: 'identical_expenses' });
    return { n, series, metrics, flags, rating, valuation: valuation(metrics, rating) };
  }

  /* Indicative valuation only (profit multiple by grade, cross-checked with a revenue multiple). Not an appraisal. */
  function valuation(m, rating) {
    if (!m || !rating) return null;
    const mult = { A: [5, 7], B: [4, 6], C: [2.5, 4], D: [1, 2.5] }[rating.grade];
    const annualProfit = m.avgProfit * 12, annualRevenue = m.avgRevenue * 12;
    const byProfit = annualProfit > 0 ? [annualProfit * mult[0], annualProfit * mult[1]] : null;
    const byRevenue = [annualRevenue * 0.3, annualRevenue * 1.0];
    const low = byProfit ? byProfit[0] : byRevenue[0], high = byProfit ? byProfit[1] : byRevenue[0] * 1.5;
    return { low, mid: (low + high) / 2, high, basis: byProfit ? 'profit' : 'revenue', revenueRange: byRevenue };
  }

  /* Expansion simulator (e.g. a restaurant opening a second branch). Inputs are monthly dollars unless noted. */
  function simulateExpansion(i) {
    const setup = num(i.setup) + num(i.equipment) + num(i.deposit);
    const fixed = num(i.rent) + num(i.insurance) + num(i.payroll) + num(i.marketing) + num(i.otherMonthly);
    const rawPct = clamp(num(i.rawPct), 0, 95) / 100;
    const workingCapital = fixed * 3;
    const total = setup + workingCapital;
    const funding = Math.max(0, total - num(i.own));
    const ramp = Math.max(1, Math.round(num(i.ramp) || 1));
    const breakEvenSales = rawPct < 1 ? fixed / (1 - rawPct) : null;
    const scenario = (label, f) => {
      const sales = num(i.sales) * f; let cum = -setup - workingCapital, payback = null; const cash = [];
      for (let m = 1; m <= 60; m++) {
        const s = m >= ramp ? sales : sales * (0.4 + 0.6 * (m - 1) / Math.max(ramp - 1, 1));
        const profit = s * (1 - rawPct) - fixed;
        cum += profit; if (m <= 24) cash.push(cum);
        if (payback === null && cum >= 0) payback = m;
      }
      const matureProfit = sales * (1 - rawPct) - fixed;
      return { label, factor: f, sales, matureProfit, payback, cum24: cash[23], cash };
    };
    const scenarios = [scenario('optimistic', 1.2), scenario('realistic', 1), scenario('conservative', 0.7)];
    const flags = [];
    if (breakEvenSales && num(i.sales) > 0 && breakEvenSales / num(i.sales) > 0.8) flags.push('tight_margin');
    const real = scenarios[1], cons = scenarios[2];
    if (real.payback === null || real.payback > 36) flags.push('slow_payback');
    if (cons.matureProfit < 0) flags.push('loss_if_sales_drop');
    if (funding > 0 && num(i.sales) > 0 && funding > num(i.sales) * 18) flags.push('large_funding');
    return { setup, workingCapital, total, funding, fixed, breakEvenSales, scenarios, flags };
  }

  /* Rule-based "assistant": answers ONLY from the analysis/portfolio data it is given. No investment advice, no guarantees.
     (A real LLM assistant replaces this on the server when ANTHROPIC_API_KEY is set.) */
  function assist(q, ctx = {}) {
    const ar = ctx.lang !== 'en', s = String(q || '').toLowerCase(), a = ctx.analysis, p = ctx.project, m = a && a.metrics, r = a && a.rating;
    const has = (...w) => w.some(x => s.includes(x));
    const loc = ar ? 'ar-EG' : 'en-US';
    const f0 = x => Math.round(x).toLocaleString(loc), f1 = x => (Math.round(x * 10) / 10).toLocaleString(loc);
    const T = (x, y) => (ar ? x : y);
    const note = T('\n\n⚠️ هذه معلومات من بيانات المنصة وليست نصيحة استثمارية، ولا توجد أرباح مضمونة.', '\n\n⚠️ Information from platform data only, not investment advice; profits are never guaranteed.');
    const codes = fl => fl.slice(0, 4).map(x => x.code).join(ar ? '، ' : ', ');
    let out = '';
    if (p && (!a || !a.n)) out = T('لا توجد بيانات مالية كافية لهذا المشروع بعد.', 'There is not enough financial data for this project yet.');
    else if (p && has('خطر', 'مخاطر', 'risk')) out = T('مستوى المخاطرة المعلن: ' + p.risk + '. ' + (r ? 'الدرجة ' + r.score + '/100 (' + r.grade + '). ' : '') + (a.flags.length ? 'عدد التنبيهات: ' + a.flags.length + ' (' + codes(a.flags) + ').' : 'لا توجد تنبيهات.'),
      'Declared risk: ' + p.risk + '. ' + (r ? 'Score ' + r.score + '/100 (' + r.grade + '). ' : '') + (a.flags.length ? 'Alerts: ' + a.flags.length + ' (' + codes(a.flags) + ').' : 'No alerts.'));
    else if (p && has('تقييم', 'درجة', 'rating', 'score', 'grade')) {
      if (!r) out = T('البيانات أقل من 3 شهور فلا يوجد تقييم.', 'Fewer than 3 months of data, so no rating.');
      else { const w = r.components.slice().sort((x, y) => x.score / x.max - y.score / y.max)[0].key; out = T('الدرجة ' + r.score + '/100 (' + r.grade + '). أضعف عنصر: ' + w + '.', 'Score ' + r.score + '/100 (' + r.grade + '). Weakest component: ' + w + '.'); }
    }
    else if (p && has('ربح', 'عائد', 'هامش', 'profit', 'return', 'margin')) out = T('متوسط صافي الربح الشهري ' + f0(m.avgProfit) + '$ وهامش الربح ' + f1(m.netMargin) + '%. العائد المتوقع الذي ذكره المالك (' + (p.expectedReturn ?? '—') + '%) تقدير منه وليس ضمانًا.',
      'Average monthly net profit $' + f0(m.avgProfit) + ', margin ' + f1(m.netMargin) + '%. The owner\'s expected return (' + (p.expectedReturn ?? '—') + '%) is an estimate, not a guarantee.');
    else if (p && has('دين', 'مديون', 'التزام', 'debt', 'liabilit')) out = T('الالتزامات الحالية ' + f0(m.liabilities) + '$' + (m.debtRatio != null ? ' أي ' + f1(m.debtRatio * 100) + '% من المبيعات السنوية.' : '.'),
      'Current liabilities $' + f0(m.liabilities) + (m.debtRatio != null ? ' = ' + f1(m.debtRatio * 100) + '% of annual sales.' : '.'));
    else if (p && has('تعادل', 'break')) out = m.breakEven ? T('نقطة التعادل الشهرية ≈ ' + f0(m.breakEven) + '$ ومتوسط المبيعات ' + f0(m.avgRevenue) + '$ (هامش الأمان ' + f1(m.marginOfSafety) + '%).',
      'Monthly break-even ≈ $' + f0(m.breakEven) + ' vs average sales $' + f0(m.avgRevenue) + ' (margin of safety ' + f1(m.marginOfSafety) + '%).') : T('تعذر حساب نقطة التعادل.', 'Break-even could not be computed.');
    else if (p && has('نمو', 'مبيعات', 'growth', 'sales', 'trend')) out = T('اتجاه المبيعات ' + f1(m.growthPerMonth) + '% شهريًا، ومتوسط المبيعات ' + f0(m.avgRevenue) + '$.', 'Sales trend ' + f1(m.growthPerMonth) + '% per month; average sales $' + f0(m.avgRevenue) + '.');
    else if (p && has('قيمة', 'تقدير', 'valu', 'worth')) out = a.valuation ? T('تقدير استرشادي للقيمة: من ' + f0(a.valuation.low) + '$ إلى ' + f0(a.valuation.high) + '$ (آلي وليس تقييمًا رسميًا).',
      'Indicative value: $' + f0(a.valuation.low) + ' – $' + f0(a.valuation.high) + ' (automated, not an appraisal).') : T('لا يوجد تقدير.', 'No estimate available.');
    else if (p && has('تلاعب', 'احتيال', 'تحذير', 'تنبيه', 'fraud', 'flag', 'alert', 'warning')) out = a.flags.length ? T('التنبيهات: ' + codes(a.flags), 'Alerts: ' + codes(a.flags)) : T('لا توجد تنبيهات حاليًا.', 'No alerts right now.');
    else if (ctx.portfolio && has('محفظة', 'تنويع', 'portfolio', 'divers', 'concentr')) {
      const h = ctx.portfolio, tot = h.reduce((x, y) => x + y.invested, 0) || 1, top = h.slice().sort((x, y) => y.invested - x.invested)[0];
      out = h.length ? T('لديك ' + h.length + ' مشروع/مشروعات بإجمالي ' + f0(tot) + '$. أكبر وزن: ' + top.title + ' (' + f0(top.invested / tot * 100) + '%).' + (top.invested / tot > 0.5 ? ' التركّز مرتفع في مشروع واحد.' : ''),
        'You hold ' + h.length + ' project(s), $' + f0(tot) + ' in total. Largest: ' + top.title + ' (' + f0(top.invested / tot * 100) + '%).' + (top.invested / tot > 0.5 ? ' Concentration in one project is high.' : '')) : T('ليس لديك استثمارات بعد.', 'You have no investments yet.');
    } else out = T('أستطيع الإجابة عن: المخاطر، التقييم، الربحية، الديون، نقطة التعادل، نمو المبيعات، القيمة الاسترشادية، التنبيهات، وتنويع محفظتك — بناءً على بيانات المنصة فقط.',
      'I can answer about: risk, rating, profitability, debt, break-even, growth, indicative value, alerts and portfolio diversification — from platform data only.');
    return out + note;
  }

  return { analyze, simulateExpansion, assist, expenses, FIELDS };
});
