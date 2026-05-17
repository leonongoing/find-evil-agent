# Devpost Submission Checklist — FinSOC Agent

**Hackathon:** FIND EVIL! by SANS Institute  
**URL:** https://findevil.devpost.com/  
**Deadline:** June 15, 2026 @ 11:45pm EDT  
**Email:** leonongoing@gmail.com

---

## Step 1: Register on Devpost

1. Go to https://devpost.com/
2. Click **Sign Up** (top right)
3. Use email: `leonongoing@gmail.com`
4. Verify email, complete profile (name, bio optional)
5. Go to https://findevil.devpost.com/ and click **Join Hackathon**

---

## Step 2: Create the Project

1. On the hackathon page, click **Submit Project**
2. Fill in:
   - **Project Name:** `FinSOC Agent`
   - **Tagline:** `AI-powered incident response with confidence scoring — no hallucinations`
   - **Built With:** `python, mcp, openai, anthropic, tshark, volatility3, yara, sleuthkit`

---

## Step 3: Fill Project Description

Copy content from `docs/devpost-writeup.md` into the Devpost rich text editor.

The writeup has these sections (Devpost standard format):
- **Inspiration** — AI attackers 8 min domain compromise
- **What it does** — FinSOC Agent, 10 MCP tools, Confidence Scoring
- **How we built it** — OpenClaw + MCP Server + SIFT tools
- **Challenges** — Hallucination problem + solution
- **Accomplishments** — DNS tunneling 72/100, C2 detection 70/100
- **What we learned** — SIFT + MCP architecture
- **What's next** — Memory forensics, real-time alerts, enterprise

> Tip: Devpost supports Markdown in some fields. If it doesn't render, paste as plain text and add manual line breaks.

---

## Step 4: Add GitHub Repository

1. Push the project to GitHub:
   ```bash
   cd /home/taomi/projects/find-evil-agent
   git init
   git add .
   git commit -m "FinSOC Agent — FIND EVIL! Hackathon submission"
   git remote add origin https://github.com/YOUR_USERNAME/finsoc-agent.git
   git push -u origin main
   ```
2. In Devpost, paste the GitHub repo URL in the **Try it out** or **Source Code** field

> Make sure the repo is **public** before submitting.

---

## Step 5: Record and Upload Demo Video

**Script:** See `docs/demo-video-script.md`

**Recording setup:**
- Terminal: dark theme, 18pt font
- Resolution: 1080p minimum
- Duration: ~3 minutes

**Recording tools:**
```bash
# Option 1: OBS Studio (recommended)
# Option 2: QuickTime (Mac)
# Option 3: ffmpeg screen capture
ffmpeg -f x11grab -r 30 -s 1920x1080 -i :0.0 -f pulse -i default output.mp4
```

**Upload:**
1. Upload to YouTube (unlisted is fine) or directly to Devpost
2. Paste the video URL in the **Demo Video** field on Devpost

---

## Step 6: Final Review Before Submit

- [ ] Project name: `FinSOC Agent`
- [ ] Description filled (from devpost-writeup.md)
- [ ] GitHub repo linked and public
- [ ] Demo video uploaded
- [ ] Built With tags added
- [ ] Team members added (if any)
- [ ] Read the rules one more time: https://findevil.devpost.com/rules

---

## Step 7: Submit

Click **Submit Project** on Devpost. You'll get a confirmation email at `leonongoing@gmail.com`.

> You can edit the submission until the deadline (June 15, 2026 @ 11:45pm EDT). Submit early, update later.

---

## Scoring Criteria (for reference)

| Criterion | Weight | How FinSOC Agent addresses it |
|-----------|--------|-------------------------------|
| Autonomous Execution Quality | High | Agent auto-discovers artifacts, runs tools, produces report |
| IR Accuracy | High | DNS tunneling 72/100, C2 detection 70/100 |
| Audit Trail Quality | High | Every finding has tool command + raw output + timestamp |
| Breadth & Depth | Medium | 10 tools across memory/network/filesystem/malware |
| Constraint Implementation | Medium | Confidence threshold (30) suppresses noise |
| Usability & Documentation | Medium | README + SKILL.md + this checklist |
