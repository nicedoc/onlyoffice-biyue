const { timeout } = require("puppeteer");
const puppeteer = require("puppeteer");

(async () => {
  const browser = await puppeteer.launch({
    bindAddress: "0.0.0.0",
    headless: true,
    // slowMo: 500,
    args: [
      //"--headless",
      "--disable-gpu",
      "--disable-dev-shm-usage",
      "--remote-debugging-port=9222",
      "--remote-debugging-address=0.0.0.0",
    ]
  });
  
  //  const url = "http://192.168.110.86/example/editor?fileName=2020%E5%B9%B4%E7%A6%8F%E5%BB%BA%E7%9C%81%E5%8D%97%E5%B9%B3%E5%B8%82%E4%B8%AD%E8%80%83%E6%95%B0%E5%AD%A6%E4%BA%8C%E6%A8%A1%E8%AF%95%E5%8D%B7%20%20%E8%A7%A3%E6%9E%90%E7%89%88.docx&userid=uid-1&lang=zh&directUrl=false";
  const url = "http://oogw.dcx.com/convert?file_id=8f2ddd59-e009-4ad4-85b7-51f051fc9234&xtoken=621b03c497503a0cb884f6d5508e1a9e";  
  const page = await browser.newPage();
  await page.setViewport({ width: 1024, height: 768 });
  // 用编辑器打开文档
  await page.goto(url, { waitUntil: "networkidle2" });

  // 选择编辑器的iframe
  const iframeSelector = "iframe[name='frameEditor']";
  await page.waitForSelector(iframeSelector);
  const frame = await page.$(iframeSelector);
  const frameContent = await frame.contentFrame();  
  await page.bringToFront();
  
  // 点击导出PDF
  const element = await frameContent.waitForSelector("a[data-tab='plugins']");
  await element.click();
  // const button = await frameContent.waitForSelector("div.svg-format-pdf");
  // await button.click();
  await page.screenshot({ path: "src/doc.png" });
  await browser.close();
})();
