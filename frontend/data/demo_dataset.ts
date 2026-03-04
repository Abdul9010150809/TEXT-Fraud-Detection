export const DEMO_DATASET = [
    // Real examples from spam_texts.csv dataset
    {
        id: 'real-1',
        label: 'Real: Wallet Credit Scam',
        text: "CREDITED: Rs.75 wallet money. Use it to order medicines and get FLAT 22% OFF. Code: PHMY22 *TC PharmEasy https://peasy.in/RjXCN6",
        riskLevel: 'MEDIUM',
        fraudType: 'Promotional Scam',
        explanation: "Uses shortened URL (peasy.in) and promotional tactics. While could be legitimate, the URL shortener hides the true destination."
    },
    {
        id: 'real-2',
        label: 'Real: Discount Offer',
        text: "Get clientele HELP Cover today. Debi check and we will cover your premium this December. Yes =call. No=out. AUTHFSP. T&C bit.ly/tc.CL.NO.=OptOut",
        riskLevel: 'MEDIUM',
        fraudType: 'Financial Scam',
        explanation: "Uses bit.ly shortener and unclear terms. Requests immediate action (Yes=call) which is a pressure tactic."
    },
    {
        id: 'real-3',
        label: 'Real: Data Deal',
        text: "Get a SPECIAL DATA DEAL of 2GB for sh. 100 valid 24hrs by clicking on https://bit.ly/Safaricomapp or Dial *544*21# and keep the connections going.",
        riskLevel: 'MEDIUM',
        fraudType: 'Promotional',
        explanation: "Uses URL shortener (bit.ly) which could hide malicious links. Limited time offer (24hrs) creates urgency."
    },
    {
        id: 'real-4',
        label: 'Real: Account Statement Scam',
        text: "PRIVATE! Your 2003 Account Statement for 07815296484 shows 800 un-redeemed S.I.M. points. Call 08718738001 Identifier Code 41782 Expires 18/11/04",
        riskLevel: 'HIGH',
        fraudType: 'Phishing',
        explanation: "Classic phishing attempt. Uses urgency (expiration date), unredeemed points lure, and requests calling a premium number."
    },
    {
        id: 'real-5',
        label: 'Real: Ringtone Subscription',
        text: "Thanks for your subscription to Ringtone UK your mobile will be charged £5/month Please confirm by replying YES or NO. If you reply NO you will not be charged",
        riskLevel: 'HIGH',
        fraudType: 'Subscription Scam',
        explanation: "Claims you subscribed without consent. Charges £5/month. Trick: replying YES or NO both confirm your number is active."
    },
    {
        id: 'real-6',
        label: 'Real: Free Mobile Scam',
        text: "07732584351 - Rodger Burns - MSG = We tried to call you re your reply to our sms for a free nokia mobile + free camcorder. Please call now 08000930705 for delivery tomorrow",
        riskLevel: 'CRITICAL',
        fraudType: 'Prize Scam',
        explanation: "Classic 'free prize' scam. Claims you replied to get free items. Urgency (delivery tomorrow) and premium rate number call."
    },

    // Safe examples from real dataset
    {
        id: 'safe-1',
        label: 'Safe: Normal Conversation',
        text: "Hello! How's you and how did saturday go? I was just texting to see if you'd decided to do anything tomo. Not that i'm trying to invite myself or anything!",
        riskLevel: 'LOW',
        fraudType: 'None',
        explanation: "Normal casual conversation between friends. No fraud indicators present."
    },
    {
        id: 'safe-2',
        label: 'Safe: Bank Query',
        text: "Sir, I need AXIS BANK account no and bank address.",
        riskLevel: 'LOW',
        fraudType: 'None',
        explanation: "Simple information request. No urgency, threats, or suspicious links."
    }
];
