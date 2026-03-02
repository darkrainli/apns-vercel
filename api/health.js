// 极简存活检测，用于确认 Vercel 项目能正常执行
module.exports = (req, res) => {
  res.status(200).json({ ok: true, message: 'apns-vercel 运行正常' });
};
