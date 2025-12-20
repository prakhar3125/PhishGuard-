from typing import Dict, List, Any
import math

class RiskScorer:
    def __init__(self):
        """
        Initialize RiskScorer with optimized data structures and max-strategy logic
        """
        # Weights for different detection methods (used for calculation, not just max)
        self.weights = {
            'threat_intel': 0.35,
            'ml': 0.30,
            'attachment': 0.20,
            'heuristic': 0.15
        }
        
        # Verdict thresholds
        self.thresholds = {
            'malicious': 75,
            'suspicious': 45
        }

        # --- OPTIMIZATION: Sets for O(1) lookup ---
        self.legitimate_domains = {
            # ============================================================================
            # GOVERNMENT & EDUCATIONAL DOMAINS (Global)
            # ============================================================================
            # Generic TLDs
            '.gov', '.edu', '.mil', '.int',
            
            # United States
            '.gov.us', '.state.us', '.fed.us',
            
            # United Kingdom
            '.gov.uk', '.ac.uk', '.police.uk', '.nhs.uk', '.mod.uk', '.parliament.uk',
            
            # Canada
            '.gc.ca', '.gov.ca', '.ca.gov',
            
            # Australia
            '.gov.au', '.edu.au', '.csiro.au',
            
            # European Union
            '.europa.eu', '.eu.int',
            
            # Other Countries
            '.gov.in', '.gov.sg', '.gov.nz', '.gov.za', '.gov.cn', '.gov.jp',
            '.gouv.fr', '.gouv.qc.ca', '.gob.mx', '.gob.es', '.gov.br',
            
            # ============================================================================
            # MAJOR TECH COMPANIES (Most Impersonated)
            # ============================================================================
            # Microsoft (40% of phishing in Q3 2025)
            'microsoft.com', 'office.com', 'office365.com', 'outlook.com', 
            'live.com', 'hotmail.com', 'msn.com', 'windows.com',
            'xbox.com', 'microsoft365.com', 'microsoftonline.com',
            'onmicrosoft.com', 'sharepoint.com', 'microsoftstore.com',
            'skype.com', 'bing.com', 'azure.com', 'visualstudio.com',
            'github.com', 'linkedin.com', 'linkedin.microsoft.com',
            
            # Google (9% of phishing)
            'google.com', 'gmail.com', 'googlemail.com', 'youtube.com',
            'google.co.uk', 'google.ca', 'google.com.au', 'google.de',
            'google.fr', 'google.es', 'google.it', 'google.co.jp',
            'google.co.in', 'google.com.br', 'google.com.mx',
            'goo.gl', 'googledrive.com', 'googleusercontent.com',
            'googlevideo.com', 'google-analytics.com', 'googleadservices.com',
            'android.com', 'chromium.org', 'blogger.com', 'blogspot.com',
            
            # Apple (6% of phishing)
            'apple.com', 'icloud.com', 'me.com', 'mac.com', 'icloud-mail.com',
            'apple.co.uk', 'apple.co.jp', 'apple.com.au',
            'itunes.com', 'appstore.com', 'icloud.email',
            
            # Meta/Facebook
            'meta.com', 'facebook.com', 'fb.com', 'instagram.com',
            'whatsapp.com', 'messenger.com', 'oculus.com',
            'facebook.net', 'fbcdn.net', 'whatsapp.net',
            
            # Amazon (3% of phishing)
            'amazon.com', 'amazon.co.uk', 'amazon.ca', 'amazon.de',
            'amazon.fr', 'amazon.es', 'amazon.it', 'amazon.co.jp',
            'amazon.com.au', 'amazon.in', 'amazon.com.br', 'amazon.com.mx',
            'amazonses.com', 'amazonaws.com', 'aws.amazon.com',
            'awsstatic.com', 'cloudfront.net', 'amazonprime.com',
            'primevideo.com', 'amazontrust.com', 'a2z.com',
            
            # Twitter/X
            'twitter.com', 'x.com', 't.co', 'twimg.com',
            
            # Adobe (3% of phishing)
            'adobe.com', 'adobelogin.com', 'adobesc.com', 'acrobat.com',
            'photoshop.com', 'behance.net', 'typekit.net', 'creativecloud.com',
            
            # Spotify (4% of phishing)
            'spotify.com', 'spotify.net', 'spotifycdn.com', 'scdn.co',
            
            # Other Major Tech
            'slack.com', 'slack-msgs.com', 'slackb.com',
            'zoom.us', 'zoom.com', 'zoomgov.com',
            'dropbox.com', 'getdropbox.com', 'dropboxusercontent.com',
            'salesforce.com', 'force.com', 'salesforceliveagent.com',
            'oracle.com', 'oraclecloud.com', 'oracle.net',
            'ibm.com', 'ibm.net', 'watson.com',
            'vmware.com', 'broadcom.com',
            'cisco.com', 'webex.com', 'ciscospark.com',
            'atlassian.com', 'atlassian.net', 'jira.com', 'confluence.com',
            'notion.so', 'notion.com',
            'canva.com', 'canva.cn',
            'docusign.com', 'docusign.net',
            'hubspot.com', 'hs-sites.com', 'hs-analytics.net',
            'shopify.com', 'shopifycdn.com', 'myshopify.com',
            'wordpress.com', 'wordpress.org', 'wp.com', 'automattic.com',
            'squarespace.com', 'sqsp.com',
            'godaddy.com', 'secureserver.net',
            'namecheap.com',
            'cloudflare.com', 'cloudflare.net',
            
            # ============================================================================
            # FINANCIAL INSTITUTIONS & PAYMENT SERVICES
            # ============================================================================
            # Payment Processors (3% of phishing for PayPal)
            'paypal.com', 'paypal.co.uk', 'paypal.ca', 'paypal.com.au',
            'paypal.de', 'paypal.fr', 'paypal.it', 'paypal-gifts.com',
            'stripe.com', 'stripe.network',
            'square.com', 'squareup.com', 'cash.app', 'cashapp.com',
            'venmo.com', 'zelle.com', 'zellepay.com',
            'wise.com', 'transferwise.com',
            'revolut.com', 'revolut.co.uk',
            'payoneer.com', 'skrill.com', 'neteller.com',
            'klarna.com', 'affirm.com', 'afterpay.com',
            
            # Major US Banks
            'chase.com', 'jpmorganchase.com', 'jpmorgan.com',
            'bankofamerica.com', 'bofa.com', 'merrilledge.com',
            'wellsfargo.com', 'wf.com',
            'citi.com', 'citibank.com', 'citigroup.com',
            'usbank.com', 'usaa.com',
            'capitalone.com', 'capital1.com',
            'pnc.com', 'pncbank.com',
            'truist.com', 'suntrust.com', 'bb-t.com',
            'tdbank.com', 'td.com',
            'regions.com', 'regionsnet.com',
            'ally.com', 'allybank.com',
            'discover.com', 'discovercard.com',
            'americanexpress.com', 'aexp.com', 'amex.com',
            'marcus.com', 'goldmansachs.com',
            'schwab.com', 'fidelity.com', 'vanguard.com',
            'morganstanley.com', 'ml.com',
            'etrade.com', 'tdameritrade.com',
            'robinhood.com',
            
            # International Banks
            'hsbc.com', 'hsbc.co.uk', 'hsbcnet.com',
            'barclays.com', 'barclays.co.uk', 'barclaycard.co.uk',
            'lloydsbank.com', 'lloydsbanking.com', 'halifax.co.uk',
            'natwest.com', 'natwestgroup.com', 'rbs.com',
            'santander.com', 'santander.co.uk', 'santanderbank.com',
            'bbva.com', 'bbvausa.com',
            'bnpparibas.com', 'bnpparibas.net',
            'ing.com', 'ing.nl', 'ingbank.com',
            'deutschebank.com', 'db.com',
            'ubs.com', 'credit-suisse.com',
            'scotiabank.com', 'scotiaonline.scotiabank.com',
            'rbc.com', 'rbcroyalbank.com',
            'cibc.com', 'cibconline.cibc.com',
            'bmo.com', 'bmoharris.com',
            'commbank.com.au', 'cba.com.au',
            'westpac.com.au', 'anz.com.au', 'nab.com.au',
            'standardchartered.com',
            'dbs.com', 'dbs.com.sg',
            'icicibank.com', 'hdfcbank.com', 'sbi.co.in',
            
            # Credit Cards
            'visa.com', 'visa.co.uk', 'visaeurope.com',
            'mastercard.com', 'mastercard.us', 'mastercardservices.com',
            'americanexpress.com', 'amex.com', 'aexp.com',
            'discovernetwork.com',
            
            # Cryptocurrency (Legitimate Exchanges)
            'coinbase.com', 'coinbase.net',
            'binance.com', 'binance.us',
            'kraken.com', 'crypto.com',
            'gemini.com', 'bitstamp.net',
            'blockchain.com', 'blockchain.info',
            
            # ============================================================================
            # E-COMMERCE & RETAIL
            # ============================================================================
            # Major Retailers
            'ebay.com', 'ebay.co.uk', 'ebay.com.au', 'ebay.de',
            'walmart.com', 'walmart.ca',
            'target.com', 'targetimg.com',
            'bestbuy.com', 'bestbuy.ca',
            'homedepot.com', 'homedepotrebates.com',
            'lowes.com',
            'costco.com', 'costco.ca', 'costco.co.uk',
            'samsclub.com',
            'wayfair.com', 'wayfair.co.uk',
            'ikea.com', 'ikea.co.uk', 'ikea.de',
            'macys.com', 'nordstrom.com', 'kohls.com',
            
            # International E-commerce
            'alibaba.com', 'aliexpress.com', 'alipay.com',
            'taobao.com', 'tmall.com', 'alicdn.com',
            'rakuten.com', 'rakuten.co.jp',
            'mercadolibre.com', 'mercadolivre.com.br',
            
            # Marketplaces
            'etsy.com', 'etsystatic.com',
            'craigslist.org',
            'offerup.com', 'letgo.com',
            
            # Booking & Travel (2% of phishing for Booking.com)
            'booking.com', 'bookingholdings.com',
            'expedia.com', 'expediagroup.com', 'hotels.com',
            'airbnb.com', 'airbnb.co.uk',
            'tripadvisor.com', 'tripadvisor.co.uk',
            'priceline.com', 'kayak.com',
            'agoda.com', 'hotwire.com',
            'vrbo.com', 'homeaway.com',
            
            # ============================================================================
            # STREAMING & ENTERTAINMENT
            # ============================================================================
            'netflix.com', 'netflix.net', 'nflxvideo.net', 'nflximg.net',
            'hulu.com', 'hulustream.com',
            'disneyplus.com', 'disney.com', 'disneynow.com', 'go.com',
            'hbomax.com', 'hbo.com', 'max.com',
            'amazonprime.com', 'primevideo.com',
            'paramountplus.com', 'paramount.com',
            'peacocktv.com', 'nbc.com',
            'crunchyroll.com', 'funimation.com',
            'twitch.tv', 'twitchcdn.net',
            'vimeo.com', 'vimeocdn.com',
            'soundcloud.com', 'sndcdn.com',
            'pandora.com', 'applemusic.com',
            'tidal.com', 'deezer.com',
            
            # Gaming
            'steam.com', 'steampowered.com', 'steamcommunity.com', 'steamstatic.com',
            'playstation.com', 'sonyentertainmentnetwork.com',
            'xbox.com', 'xboxlive.com',
            'nintendo.com', 'nintendo.net', 'nintendoswitch.com',
            'epicgames.com', 'unrealengine.com',
            'roblox.com', 'rbxcdn.com',
            'ea.com', 'origin.com',
            'blizzard.com', 'battle.net', 'battlenet.com',
            'ubisoft.com', 'ubi.com',
            'discord.com', 'discordapp.com', 'discord.gg',
            
            # ============================================================================
            # SHIPPING & LOGISTICS (High Impersonation Rate)
            # ============================================================================
            # Major Carriers (2% for DHL)
            'fedex.com', 'fedex.ca', 'fedex.co.uk',
            'ups.com', 'ups.ca', 'ups.co.uk', 'upsscs.com',
            'usps.com', 'usps.gov',
            'dhl.com', 'dhl.de', 'dhl.co.uk', 'dhl-usa.com',
            'royalmail.com', 'royalmail.co.uk',
            'canadapost.ca', 'canadapost-postescanada.ca',
            'auspost.com.au', 'australiapost.com.au',
            'hermes.com', 'myhermes.co.uk',
            'dpd.com', 'dpd.co.uk',
            'purolator.com', 'purolator.ca',
            'ontrac.com', 'lasership.com',
            
            # ============================================================================
            # TELECOMMUNICATIONS & ISP
            # ============================================================================
            # US Carriers
            'verizon.com', 'verizonwireless.com', 'verizon.net',
            'att.com', 'att.net', 'attwireless.com',
            't-mobile.com', 'tmobile.com', 'tmo.com',
            'sprint.com',
            'comcast.com', 'comcast.net', 'xfinity.com',
            'cox.com', 'cox.net',
            'spectrum.com', 'charter.com', 'charter.net',
            'centurylink.com', 'centurylink.net',
            'frontier.com', 'frontiernet.net',
            
            # International Telecom
            'vodafone.com', 'vodafone.co.uk', 'vodafone.de',
            'bt.com', 'btinternet.com',
            'o2.com', 'o2.co.uk',
            'ee.co.uk',
            'orange.fr', 'orange.com',
            'telekom.de', 't-online.de',
            'rogers.com', 'rogers.ca',
            'bell.ca', 'bell.net',
            'telus.com', 'telus.net',
            'telstra.com.au', 'telstra.net',
            'optus.com.au',
            'singtel.com',
            
            # ============================================================================
            # POPULAR EMAIL PROVIDERS (Beyond Tech Giants)
            # ============================================================================
            'yahoo.com', 'yahoo.co.uk', 'yahoo.fr', 'yahoo.de',
            'yahoo.com.br', 'yahoo.co.jp', 'yahoo.co.in',
            'ymail.com', 'rocketmail.com',
            'aol.com', 'aim.com',
            'protonmail.com', 'proton.me', 'protonmail.ch',
            'mail.com', 'email.com',
            'gmx.com', 'gmx.de', 'gmx.net',
            'web.de',
            'yandex.com', 'yandex.ru', 'ya.ru',
            'mail.ru', 'rambler.ru',
            'qq.com', '163.com', '126.com',
            'zoho.com', 'zohomail.com',
            'tutanota.com', 'tuta.io',
            'fastmail.com', 'fastmail.fm',
            'hushmail.com',
            
            # Country-specific popular providers
            'wanadoo.fr', 'free.fr', 'sfr.fr', 'laposte.net', 'orange.fr',
            'libero.it', 'virgilio.it', 'alice.it', 'tiscali.it', 'tin.it',
            'uol.com.br', 'bol.com.br', 'terra.com.br', 'ig.com.br',
            'rediffmail.com',
            'bigpond.com', 'bigpond.net.au', 'optusnet.com.au',
            'sky.com', 'ntlworld.com', 'blueyonder.co.uk', 'tiscali.co.uk',
            'telenet.be', 'skynet.be',
            'home.nl', 'planet.nl', 'hetnet.nl', 'zonnet.nl', 'chello.nl',
            'bluewin.ch',
            'shaw.ca', 'sympatico.ca',
            'sbcglobal.net', 'earthlink.net', 'optonline.net',
            'bellsouth.net', 'windstream.net',
            
            # ============================================================================
            # SOCIAL MEDIA & PROFESSIONAL NETWORKS
            # ============================================================================
            'linkedin.com', 'licdn.com',
            'reddit.com', 'redd.it', 'redditmedia.com',
            'snapchat.com', 'snap.com',
            'tiktok.com', 'tiktokcdn.com', 'tiktokv.com',
            'pinterest.com', 'pinimg.com',
            'tumblr.com',
            'telegram.org', 'telegram.me', 't.me',
            'signal.org',
            'mastodon.social',
            'yelp.com', 'yelp.co.uk',
            
            # ============================================================================
            # EDUCATION & LEARNING PLATFORMS
            # ============================================================================
            'coursera.org', 'coursera-apps.org',
            'udemy.com', 'udemy-data.com',
            'edx.org',
            'khanacademy.org',
            'duolingo.com',
            'codecademy.com',
            'pluralsight.com',
            'udacity.com',
            'skillshare.com',
            'canvas.instructure.com',
            'blackboard.com', 'blackboard.learn.com',
            'turnitin.com',
            'chegg.com',
            
            # ============================================================================
            # HEALTH & INSURANCE
            # ============================================================================
            'unitedhealthcare.com', 'uhc.com',
            'anthem.com', 'wellpoint.com',
            'cigna.com',
            'aetna.com',
            'humana.com',
            'bcbs.com', 'bcbsm.com',
            'kaiser.com', 'kaiserpermanente.org',
            'bluecrossma.com', 'premera.com',
            'cvs.com', 'cvshealth.com', 'caremark.com',
            'walgreens.com', 'walgreens.net',
            'rite-aid.com',
            'mayoclinic.org', 'clevelandclinic.org',
            'nih.gov', 'cdc.gov', 'who.int',
            'nhs.uk', 'nhs.net',
            
            # ============================================================================
            # CYBERSECURITY & ANTIVIRUS
            # ============================================================================
            'norton.com', 'nortonlifelock.com', 'symantec.com',
            'mcafee.com',
            'avast.com', 'avg.com',
            'kaspersky.com', 'kaspersky.co.uk',
            'bitdefender.com',
            'malwarebytes.com',
            'trendmicro.com',
            'eset.com',
            'sophos.com',
            'crowdstrike.com',
            'paloaltonetworks.com',
            'fortinet.com',
            'checkpoint.com',
            
            # ============================================================================
            # NEWS & MEDIA
            # ============================================================================
            'nytimes.com', 'newyorktimes.com',
            'wsj.com', 'dowjones.com',
            'washingtonpost.com',
            'cnn.com', 'cnn.it',
            'bbc.com', 'bbc.co.uk', 'bbci.co.uk',
            'theguardian.com', 'guardian.co.uk',
            'reuters.com', 'reutersmedia.net',
            'bloomberg.com', 'bloomberg.net',
            'forbes.com',
            'time.com', 'fortune.com',
            'npr.org',
            'usatoday.com',
            
            # ============================================================================
            # BUSINESS SERVICES
            # ============================================================================
            'indeed.com', 'indeed.co.uk',
            'monster.com',
            'glassdoor.com',
            'ziprecruiter.com',
            'careerbuilder.com',
            'fedex.com', 'fedexoffice.com',
            'kinkos.com',
            'staples.com', 'officemax.com', 'officedepot.com',
            'vistaprint.com',
            'mailchimp.com', 'mandrill.com',
            'sendgrid.com', 'sendgrid.net',
            'constantcontact.com',
            'surveymonkey.com',
            'typeform.com',
            'calendly.com',
            'acuityscheduling.com',
            
            # ============================================================================
            # TRANSPORTATION & RIDE-SHARING
            # ============================================================================
            'uber.com', 'uber-asia.com',
            'lyft.com',
            'doordash.com',
            'grubhub.com',
            'ubereats.com',
            'postmates.com',
            'instacart.com',
            'delta.com', 'delta.net',
            'united.com', 'ual.com',
            'aa.com', 'americanairlines.com',
            'southwest.com',
            'jetblue.com',
            'alaskaair.com',
            'britishairways.com',
            'lufthansa.com',
            'airfrance.com', 'airfrance.fr',
            'klm.com',
            'qantas.com.au',
            'emirates.com',
            'amtrak.com',
            'greyhound.com',
            
            # ============================================================================
            # MISCELLANEOUS LEGITIMATE SERVICES
            # ============================================================================
            'weather.com', 'weather.gov',
            'irs.gov', 'ssa.gov',
            'creditkarma.com',
            'equifax.com', 'experian.com', 'transunion.com',
            'turbotax.com', 'intuit.com', 'quickbooks.com',
            'mint.com',
            'fico.com', 'myfico.com',
            'ancestry.com', '23andme.com',
            'match.com', 'eharmony.com', 'tinder.com', 'bumble.com',
            'zillow.com', 'trulia.com', 'realtor.com', 'redfin.com',
            'apartments.com',
            'autotrader.com', 'cars.com', 'carfax.com',
            'opentable.com', 'yelp.com',
            'ticketmaster.com', 'stubhub.com', 'eventbrite.com',
            'wikipedia.org', 'wikimedia.org', 'wikidata.org',
            'archive.org', 'internetarchive.org',
            'medium.com',
        }

        

        self.high_trust_domains = {
            # ============================================================
            # GOVERNMENT & INTERGOVERNMENTAL (STRICTLY CONTROLLED)
            # ============================================================
            '.gov', '.gov.us', '.gov.uk', '.gov.au', '.gov.ca', '.gov.in',
            '.gc.ca', '.gouv.fr', '.gob.es', '.gob.mx', '.gov.br',
            '.mil', '.nhs.uk', '.europa.eu', '.who.int', '.un.org', '.int',

            # ============================================================
            # MAJOR CLOUD / IDENTITY PROVIDERS (ENTERPRISE SSO)
            # ============================================================
            # Microsoft – most impersonated brand but core identity provider [web:11]
            'microsoft.com', 'office.com', 'microsoftonline.com',
            'outlook.com', 'live.com', 'hotmail.com', 'office365.com',

            # Google – second most impersonated, primary identity provider [web:11]
            'google.com', 'gmail.com', 'googlemail.com',
            'googleworkspace.com',  # Google Workspace
            'googleapis.com', 'googleusercontent.com',

            # Apple
            'apple.com', 'icloud.com', 'appleid.apple.com',

            # Identity & SSO platforms
            'okta.com', 'auth0.com', 'onelogin.com', 'duosecurity.com',

            # ============================================================
            # CORE FINANCIAL & PAYMENT BRANDS (GLOBAL, HEAVILY REGULATED)
            # ============================================================
            # Card schemes
            'visa.com', 'mastercard.com', 'americanexpress.com', 'amex.com',

            # Global payments / wallets (top phishing targets but still high trust) [web:11][web:29]
            'paypal.com', 'paypal.co.uk', 'stripe.com',
            'squareup.com', 'cash.app', 'zellepay.com',
            'wise.com', 'revolut.com',

            # Tier‑1 US banks
            'chase.com', 'bankofamerica.com', 'wellsfargo.com',
            'citi.com', 'citibank.com',
            'usbank.com', 'capitalone.com',
            'pnc.com', 'tdbank.com',
            'truist.com', 'ally.com',

            # Tier‑1 non‑US banks
            'hsbc.com', 'barclays.com', 'lloydsbank.com',
            'santander.com', 'ing.com',
            'deutschebank.com', 'ubs.com', 'credit-suisse.com',
            'scotiabank.com', 'rbc.com', 'cibc.com', 'bmo.com',

            # Tax & credit agencies (often used for sensitive flows)
            'irs.gov', 'ssa.gov',
            'experian.com', 'equifax.com', 'transunion.com',

            # ============================================================
            # MAJOR CONSUMER PLATFORMS (HIGH TRUST, HIGH IMPERSONATION)
            # ============================================================
            # Commerce / marketplaces
            'amazon.com', 'amazon.co.uk', 'amazon.de',
            'ebay.com', 'walmart.com',

            # Productivity & collaboration SaaS heavily used in business email [web:9]
            'zoom.us', 'zoom.com',
            'slack.com',
            'atlassian.com', 'atlassian.net',
            'docusign.com',
            'dropbox.com',
            'salesforce.com', 'force.com',

            # Professional networking
            'linkedin.com',

            # Shipment status notifications (common but important) [web:29]
            'fedex.com', 'ups.com', 'dhl.com', 'usps.com',

            # ============================================================
            # HEALTH & CRITICAL INFRASTRUCTURE
            # ============================================================
            'cdc.gov', 'nih.gov',
            'nhs.uk',
            'mayo.edu', 'mayoclinic.org',
        }


                # Suspicious TLDs with risk scores
        self.suspicious_tlds = {
            # ============================================================
            # CRITICAL (50 points) – very high phishing / abuse ratio
            # Budget gTLDs and confusing file‑extension TLDs
            # ============================================================
            '.tk': 50, '.ml': 50, '.ga': 50, '.cf': 50, '.gq': 50,   # classic “free” ccTLD abuse [web:38]
            '.zip': 50, '.mov': 50,                                 # file‑extension TLD confusion & abuse [web:39][web:42][web:45]
            '.cfd': 50,                                             # frequent in phishing kits & fake portals [web:33][web:35]
            '.sbs': 50, '.bond': 50, '.lol': 50,                    # very high malicious registration growth [web:35]
            '.mom': 50,                                             # high phishing score per domain [web:34]
            '.quest': 50, '.buzz': 50, '.ink': 50, '.fyi': 50,      # in top abused list by ratio [web:34][web:41]

            # ============================================================
            # HIGH RISK (35 points) – consistently high malicious use
            # ============================================================
            '.xyz': 35, '.top': 35, '.work': 35, '.click': 35, '.link': 35,
            '.download': 35, '.racing': 35, '.loan': 35, '.win': 35, '.bid': 35,
            '.info': 35, '.vip': 35, '.icu': 35, '.today': 35,      # elevated phishing registrations [web:35][web:47]
            '.shop': 35, '.live': 35, '.online': 35, '.site': 35,   # heavy use in spam/phishing campaigns [web:35][web:47]
            '.quest': 35, '.buzz': 35, '.ink': 35, '.fyi': 35,      # can also be tuned to 35 if 50 feels too aggressive

            # ============================================================
            # MODERATE RISK (25 points) – abused but also widely legitimate
            # treat as a warning, not a verdict
            # ============================================================
            '.online': 25, '.site': 25, '.website': 25, '.space': 25, '.host': 25,
            '.fun': 25, '.tech': 25, '.store': 25, '.company': 25, '.email': 25,
            '.cloud': 25, '.digital': 25, '.solutions': 25, '.services': 25,
            '.support': 25, '.center': 25, '.world': 25, '.media': 25,
            '.app': 25, '.page': 25, '.dev': 25,                    # dev/app TLDs frequently misused in phishing redirs [web:33][web:37]

            # ============================================================
            # COUNTRY / REGIONAL ABUSE (20–25 points)
            # ccTLDs with notably elevated phishing abuse
            # (DO NOT block outright – many legit users; just risk‑weight)
            # ============================================================
            '.cc': 25, '.cd': 25, '.nu': 25, '.ws': 25, '.cm': 25,  # long‑running high misuse rates [web:38][web:41]
            '.es': 25,                                              # large recent spike in phishing campaigns [web:40][web:43]
            '.ru': 20, '.cn': 20, '.su': 20,                        # consistently high in malicious registrations [web:35][web:41]
            '.tv': 20, '.io': 20,                                   # often used by shady SaaS / crypto scams [web:37][web:44]

            # ============================================================
            # “WATCHLIST” (15 points) – noticeable abuse but too broad to
            # treat as strongly suspicious on their own
            # ============================================================
            '.net': 15, '.org': 15, '.co': 15,                      # widely abused but very common legit usage [web:35][web:47]
            '.biz': 15, '.pro': 15, '.pw': 15,
        }


        # Brand mapping for typosquatting checks
        self.brand_domains = {
            # ============================================================
            # PAYMENT & FINANCIAL
            # ============================================================
            'paypal': [
                'paypal.com', 'paypal.co.uk', 'paypal.ca', 'paypal.de',
                'paypal.fr', 'paypal.it'
            ],
            'visa': [
                'visa.com', 'visa.co.uk'
            ],
            'mastercard': [
                'mastercard.com', 'mastercard.us'
            ],
            'americanexpress': [
                'americanexpress.com', 'amex.com', 'aexp.com'
            ],
            'stripe': [
                'stripe.com', 'stripe.network'
            ],
            'square': [
                'squareup.com', 'square.com', 'cash.app'
            ],
            'zelle': [
                'zellepay.com', 'zelle.com'
            ],
            'wise': [
                'wise.com', 'transferwise.com'
            ],
            'revolut': [
                'revolut.com', 'revolut.co.uk'
            ],
            'chase': [
                'chase.com', 'jpmorganchase.com', 'jpmorgan.com',
                'alertsp.chase.com'
            ],
            'bankofamerica': [
                'bankofamerica.com', 'bofa.com'
            ],
            'wellsfargo': [
                'wellsfargo.com', 'wf.com'
            ],
            'citi': [
                'citi.com', 'citibank.com'
            ],
            'capitalone': [
                'capitalone.com'
            ],

            # ============================================================
            # BIG TECH / CLOUD / IDENTITY
            # (Top 3 most impersonated: Microsoft, Google, Apple) [web:11][web:59]
            # ============================================================
            'microsoft': [
                'microsoft.com', 'office.com', 'office365.com',
                'microsoftonline.com', 'outlook.com', 'live.com',
                'hotmail.com', 'onmicrosoft.com', 'xbox.com'
            ],
            'google': [
                'google.com', 'gmail.com', 'googlemail.com',
                'google.co.uk', 'google.co.in',
                'googleapis.com', 'googleusercontent.com',
                'drive.google.com', 'docs.google.com'
            ],
            'apple': [
                'apple.com', 'icloud.com', 'me.com', 'mac.com',
                'appleid.apple.com'
            ],
            'meta': [
                'facebook.com', 'fb.com', 'meta.com',
                'instagram.com', 'whatsapp.com'
            ],
            'amazon': [
                'amazon.com', 'amazon.co.uk', 'amazon.ca', 'amazon.de',
                'amazon.fr', 'amazon.it', 'amazon.es',
                'amazon.in', 'primevideo.com', 'amazonprime.com'
            ],
            'adobe': [
                'adobe.com', 'adobelogin.com', 'acrobat.com'
            ],
            'spotify': [
                'spotify.com', 'spotifycdn.com', 'scdn.co'
            ],
            'netflix': [
                'netflix.com', 'netflix.net', 'nflxvideo.net', 'nflximg.net'
            ],
            'linkedin': [
                'linkedin.com', 'licdn.com'
            ],
            'zoom': [
                'zoom.us', 'zoom.com', 'zoomgov.com'
            ],
            'slack': [
                'slack.com', 'slack-msgs.com'
            ],
            'docusign': [
                'docusign.com', 'docusign.net'
            ],
            'dropbox': [
                'dropbox.com', 'dropboxusercontent.com'
            ],
            'salesforce': [
                'salesforce.com', 'force.com'
            ],

            # ============================================================
            # E‑COMMERCE & RETAIL (heavily spoofed around shopping seasons) [web:17][web:61]
            # ============================================================
            'walmart': [
                'walmart.com', 'walmart.ca'
            ],
            'ebay': [
                'ebay.com', 'ebay.co.uk'
            ],
            'alibaba': [
                'alibaba.com', 'aliexpress.com'
            ],

            # ============================================================
            # SHIPPING & DELIVERY (DHL, FedEx, etc. often abused) [web:11][web:62]
            # ============================================================
            'dhl': [
                'dhl.com', 'dhl.de', 'dhl.co.uk'
            ],
            'fedex': [
                'fedex.com', 'fedex.com.au', 'fedex.ca'
            ],
            'ups': [
                'ups.com', 'ups.co.uk'
            ],
            'usps': [
                'usps.com'
            ],

            # ============================================================
            # COMMUNICATION & SOCIAL
            # ============================================================
            'telegram': [
                'telegram.org', 't.me'
            ],
            'discord': [
                'discord.com', 'discordapp.com'
            ],
            'twitter': [
                'twitter.com', 'x.com', 't.co'
            ],
            'roblox': [
                'roblox.com', 'rbxcdn.com'
            ],
            'steam': [
                'steampowered.com', 'steamcommunity.com', 'steam.com'
            ],

            # ============================================================
            # TRAVEL & BOOKING (Booking.com is in top 10) [web:11]
            # ============================================================
            'booking': [
                'booking.com'
            ],
            'airbnb': [
                'airbnb.com'
            ],
            'uber': [
                'uber.com', 'ubereats.com'
            ]
        }


    def _extract_domain(self, sender: str) -> str:
        """Extract domain from email address efficiently"""
        if '@' not in sender:
            return ''
        parts = sender.split('@')
        if len(parts) > 1:
            # Handle cases like "User <user@domain.com>"
            return parts[-1].split('>')[0].lower().strip()
        return ''

    def _is_legitimate_domain(self, domain: str) -> bool:
        """Fast domain legitimacy check using set lookup"""
        if not domain:
            return False
        
        # Direct match (O(1))
        if domain in self.legitimate_domains:
            return True
            
        # Check TLD match (for .gov, .edu, etc.)
        for legit in self.legitimate_domains:
            if legit.startswith('.') and domain.endswith(legit):
                return True
        return False

    def _get_trust_level(self, domain: str) -> str:
        """Determine trust level of domain"""
        # Check against high trust sets
        if domain in self.high_trust_domains:
            return 'high'
        # Check for TLD trust
        for trusted in self.high_trust_domains:
            if trusted.startswith('.') and domain.endswith(trusted):
                return 'high'
                
        if self._is_legitimate_domain(domain):
            return 'medium'
        return 'low'

    def _levenshtein_distance(self, s1: str, s2: str) -> int:
        """Calculate Levenshtein distance between two strings"""
        if len(s1) < len(s2):
            return self._levenshtein_distance(s2, s1)
        if len(s2) == 0:
            return len(s1)
        
        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        return previous_row[-1]

    def _check_typosquatting(self, domain: str) -> dict:
        """
        Detect typosquatting attempts
        Returns: {'is_typosquatting': bool, 'brand': str, 'score': int}
        """
        result = {'is_typosquatting': False, 'brand': None, 'score': 0}
        
        if not domain:
            return result

        # Common character substitutions
        # Common character substitutions used in typosquatting / homoglyph attacks
        substitutions = {
            # Digits <-> letters
            'o': '0', '0': 'o',
            'l': '1', '1': 'l',          # l ↔ 1
            'i': '1', '1': 'i',
            'e': '3', '3': 'e',
            'a': '4', '4': 'a',
            's': '5', '5': 's',
            't': '7', '7': 't',
            'b': '8', '8': 'b',

            # Symbol swaps commonly seen in phishing
            'a': '@', '@': 'a',
            's': '$', '$': 's',
            'c': '(', '(': 'c',
            'x': '%', '%': 'x',

            # Simple multi‑char patterns (handle separately in code, not direct 1:1 replace)
            # e.g. "vv" → "w", "rn" → "m" etc.
        }

        
        domain_parts = domain.split('.')
        if len(domain_parts) < 2: 
            return result
            
        # Focus on the main domain part (e.g., 'amazon' from 'amazon.co.uk')
        domain_base = domain_parts[0] 

        # Check against each brand
        for brand, official_domains in self.brand_domains.items():
            for official in official_domains:
                official_base = official.split('.')[0]
                
                # Skip exact matches
                if domain_base == official_base:
                    continue

                # Check substitution attacks
                modified_base = domain_base
                for char, sub in substitutions.items():
                    modified_base = modified_base.replace(sub, char)
                
                if modified_base == official_base:
                     result['is_typosquatting'] = True
                     result['brand'] = brand
                     result['score'] = 45
                     return result

                # Check Levenshtein distance
                # Only check if lengths are close to avoid false positives on short strings
                if abs(len(domain_base) - len(official_base)) <= 2:
                    dist = self._levenshtein_distance(domain_base, official_base)
                    if dist > 0 and dist <= 2: # Distance 1 or 2 is suspicious
                        result['is_typosquatting'] = True
                        result['brand'] = brand
                        result['score'] = 40
                        return result
        return result

    def calculate_risk_score(self, analysis_data: Dict) -> Dict:
        """Calculate comprehensive risk score"""
        scores = {
            'threat_intel_score': 0,
            'ml_score': 0,
            'attachment_score': 0,
            'heuristic_score': 0,
            'total_score': 0
        }
        
        # --- EARLY EXIT: Whitelist Check ---
        sender = analysis_data.get('sender', '').lower()
        sender_domain = self._extract_domain(sender)
        
        if self._get_trust_level(sender_domain) == 'high':
             # Fast-track trusted domains
             return {
                "score": 0,
                "verdict": "CLEAN",
                "breakdown": {
                    "threat_intel": 0,
                    "ml_analysis": 0,
                    "attachment_risk": 0,
                    "heuristic_risk": 0
                },
                "explanation": f"Trusted domain detected: {sender_domain}"
            }

        # 1. Threat Intelligence Score
        threat_intel_results = analysis_data.get('threat_intel_results', [])
        if threat_intel_results:
            if any(r.get('is_malicious') for r in threat_intel_results):
                scores['threat_intel_score'] = 100
            else:
                avg_reputation = sum(r.get('reputation_score', 0) for r in threat_intel_results)
                scores['threat_intel_score'] = min(int(avg_reputation / len(threat_intel_results)), 100)
        
        # 2. ML Prediction Score
        ml_result = analysis_data.get('ml_prediction', {})
        if ml_result:
            phishing_prob = ml_result.get('phishing_probability', 0)
            scores['ml_score'] = int(phishing_prob * 100)
        
        # 3. Attachment Analysis Score
        attachment_results = analysis_data.get('attachment_analysis', [])
        if attachment_results:
            max_attachment_risk = max((a.get('risk_score', 0) for a in attachment_results), default=0)
            scores['attachment_score'] = max_attachment_risk
        
        # 4. Heuristic Score
        scores['heuristic_score'] = self._calculate_heuristic_score(analysis_data)
        
        # --- MAX STRATEGY ---
        scores['total_score'] = max(
            scores['threat_intel_score'],
            scores['ml_score'],
            scores['attachment_score'],
            scores['heuristic_score']
        )
        
        return {
            "score": scores['total_score'],
            "verdict": self._determine_verdict(scores['total_score']),
            "breakdown": {
                "threat_intel": scores['threat_intel_score'],
                "ml_analysis": scores['ml_score'],
                "attachment_risk": scores['attachment_score'],
                "heuristic_risk": scores['heuristic_score']
            }
        }
    
    def _calculate_heuristic_score(self, analysis_data: Dict) -> int:
        """Enhanced and optimized heuristic scoring"""
        score = 0
        indicators = []
        
        sender = analysis_data.get('sender', '').lower()
        subject = analysis_data.get('subject', '').lower()
        body = analysis_data.get('body', '').lower()
        full_text = f"{subject} {body}"
        
        # Extract domain once
        sender_domain = self._extract_domain(sender)
        
        # ===== 1. SUSPICIOUS TLDs WITH WEIGHTED SCORING =====
        for tld, tld_score in self.suspicious_tlds.items():
            if sender_domain.endswith(tld):
                score += tld_score
                break  # Only count the highest risk TLD match

        # ===== 2. TYPOSQUATTING DETECTION =====
        typo_check = self._check_typosquatting(sender_domain)
        if typo_check['is_typosquatting']:
            score += typo_check['score']
            indicators.append(f"Typosquatting detected: impersonating {typo_check['brand']}")

        # ===== 3. CRITICAL KEYWORDS (40 points each) =====
        critical_keywords = {
            # High‑value / irreversible payment methods
            'wire transfer': 40,
            'bank wire': 40,
            'swift transfer': 40,
            'international wire': 40,
            'urgent wire': 40,
            'western union': 40,
            'moneygram': 40,
            'money gram': 40,
            'money order': 35,
            'cashier\'s check': 35,
            'money mule': 40,

            # Gift cards & vouchers
            'gift card': 40,
            'google play card': 40,
            'amazon gift card': 40,
            'steam card': 35,
            'itunes card': 35,
            'apple gift card': 35,
            'xbox gift card': 35,
            'playstation gift card': 35,
            'prepaid card': 35,
            'pre-paid card': 35,
            'voucher code': 35,
            'scratch card': 35,

            # Crypto & investment scams
            'bitcoin': 40,
            'btc': 35,
            'cryptocurrency': 35,
            'crypto wallet': 35,
            'wallet address': 35,
            'usdt': 35,
            'tether': 35,
            'ethereum': 35,
            'eth': 35,
            'binance coin': 35,
            'deposit crypto': 35,
            'send crypto': 35,
            'investment opportunity': 35,
            'guaranteed returns': 40,
            'double your money': 40,
            'get rich quick': 40,

            # Cash‑like reloadable products
            'green dot': 40,
            'green dot money pack': 40,
            'money pak': 40,
            'reloadit': 40,
            'vanilla reload': 40,
            'prepaid debit': 35,
            'reloadable card': 35,

            # Ransom / extortion style wording
            'pay the ransom': 40,
            'ransom payment': 40,
            'bitcoin ransom': 40,
            'we have your data': 40,
            'we have your passwords': 40,
            'we hacked your account': 40,
            'send payment within 24 hours': 40,
            'send payment within 48 hours': 40,

            # Employer / supplier payment redirection
            'change bank details': 40,
            'update bank account': 40,
            'update payment details': 35,
            'new account details': 35,
            'change payment information': 35,
            'update beneficiary': 35,

            # Tax / refund fraud
            'tax refund': 35,
            'unclaimed refund': 35,
            'overdue tax': 35,
            'irs refund': 35,
            'tax rebate': 35,
        }

        
        for keyword, points in critical_keywords.items():
            if keyword in full_text:
                score += points
                indicators.append(f"Critical keyword: {keyword}")

        # ===== 4. URGENCY TACTICS (max 40 points) =====
        urgency_words = {
            # Core urgency
            'urgent', 'urgently', 'immediately', 'immediate', 'right away',
            'right now', 'act now', 'take action now', 'do not delay',
            'don\'t delay', 'don\'t wait', 'cannot wait',

            # Time pressure / deadlines
            'asap', 'a.s.a.p', 'now or never', 'time sensitive', 'time‑sensitive',
            'time critical', 'expires today', 'expires soon', 'expire', 'expiring',
            'expiring soon', 'limited time', 'limited‑time offer',
            'offer ends soon', 'ends today', 'ends tonight',
            'deadline', 'due today', 'due now', 'overdue', 'past due',
            'within 24 hours', 'within 48 hours', 'within 72 hours',
            'respond within 24 hours', 'respond within 48 hours',
            'immediate response required', 'respond immediately',

            # Final / last warning language
            'final notice', 'final reminder', 'final warning',
            'last chance', 'last opportunity', 'last reminder',
            'only today', 'only tonight', 'only for a short time',

            # Threats & negative consequences
            'account will be closed', 'account will be locked',
            'will be locked', 'will be suspended', 'will be disabled',
            'service will be terminated', 'service termination',
            'lose access', 'lose your account', 'permanent loss',
            'permanently deleted', 'cannot be undone',

            # Account / security status
            'suspended', 'suspension', 'locked', 'locked out',
            'disabled', 'deactivated', 'blocked', 'restricted',
            'security alert', 'security warning', 'security notice',
            'unusual activity', 'suspicious activity',
            'verify immediately', 'verify now', 'confirm now',

            # Attention‑grabbing intros
            'action required', 'action needed', 'attention required',
            'requires immediate attention', 'critical notice',
            'important notice', 'important update', 'important message',
            'failure to act', 'failure to respond',

            # Countdown / scarcity language
            'only a few left', 'almost gone', 'selling fast',
            'spots are limited', 'limited spots', 'slots filling up',
            'while supplies last', 'before it\'s too late',
            'time is running out', 'clock is ticking',
        }

        urgency_count = sum(1 for word in urgency_words if word in full_text)
        urgency_score = min(urgency_count * 8, 40)
        score += urgency_score

        # ===== 5. CREDENTIAL REQUESTS (max 40 points) =====
        credential_keywords = {
            # Core login / account credentials
            'password', 'passwords', 'passcode', 'pass code', 'passphrase',
            'username', 'user name', 'user id', 'userid', 'login', 'log in',
            'sign in', 'signin', 'account id', 'account login', 'account credentials',
            'credentials', 'security credentials',

            # Multi‑factor / one‑time codes
            'one time password', 'one-time password', 'one time passcode',
            'otp', '2fa', 'two factor', 'two-factor', 'mfa', 'multi factor',
            'verification code', 'security code', 'auth code', 'access code',
            'sms code', 'email code', 'confirmation code',

            # Social security / government IDs
            'ssn', 'social security', 'social security number',
            'tax id', 'tax identification number', 'tin', 'ein', 'nin',
            'national id', 'national identification', 'id card', 'identity card',

            # Personal identity details
            'date of birth', 'dob', 'birth date', 'birthday',
            'mother\'s maiden name', 'maiden name',
            'full name', 'legal name', 'home address', 'residential address',
            'billing address', 'shipping address', 'postal address',
            'phone number', 'mobile number', 'cell number',

            # Financial & card data
            'credit card', 'debit card', 'bank card', 'card number',
            'card details', 'cardholder name', 'card holder name',
            'cvv', 'cvv2', 'cvc', 'csc', 'security code', 'card security code',
            'expiry date', 'expiration date', 'exp date', 'valid thru',
            'bank account', 'account number', 'acct number',
            'iban', 'swift code', 'routing number', 'sort code',
            'account and routing', 'direct deposit details',

            # Online payment / wallet access
            'paypal password', 'paypal account',
            'online banking login', 'internet banking login',
            'netbanking password', 'banking credentials',
            'wallet password', 'wallet seed', 'wallet phrase',

            # Crypto‑specific secrets
            'private key', 'seed phrase', 'recovery phrase',
            '12 word phrase', '24 word phrase', 'mnemonic phrase',

            # Security questions & recovery
            'security question', 'security questions',
            'security answer', 'secret question', 'secret answer',
            'recovery question', 'recovery answers',
            'reset password', 'change password', 'update password',
            'current password', 'old password', 'new password',

            # Access tokens / API keys
            'access token', 'auth token', 'api key', 'api token',
            'secret key', 'client secret', 'application secret',
            'ssh key', 'ssh private key',

            # Document / ID uploads
            'upload your id', 'scan your id', 'photo id',
            'copy of your id', 'upload passport', 'passport scan',
            'driver\'s license', 'drivers license', 'driving license',
            'proof of identity', 'proof of address',

            # Account recovery & unlock wording
            'verify your identity', 'confirm your identity',
            'verify your account', 'confirm your account',
            'reconfirm your details', 'update your information',
            'update your details', 'restore access', 'unlock your account',
        }

        cred_count = sum(1 for kw in credential_keywords if kw in body)
        cred_score = min(cred_count * 20, 40)
        score += cred_score

        # ===== 6. SENDER MISMATCH (35 points) =====
        if self._check_sender_mismatch(analysis_data):
            score += 35
            indicators.append("Sender mismatch detected")

        # ===== 7. EXCESSIVE LINKS (graduated scoring) =====
        link_count = full_text.count('http')
        if link_count > 8:
            score += 25
        elif link_count > 5:
            score += 15
        elif link_count > 3:
            score += 5

        # ===== 8. URL SHORTENERS (15 points) =====
        shorteners = {
            # Major generic shorteners
            'bit.ly', 'bitly.com', 'tinyurl.com', 'goo.gl', 't.co',
            'ow.ly', 'is.gd', 'tiny.cc', 'buff.ly', 'adf.ly',
            'bl.ink', 'lnkd.in', 'cutt.ly', 'shorte.st',

            # Branded / platform shorteners
            'youtu.be',      # YouTube
            'amzn.to',       # Amazon
            'fb.me', 'fb.com',   # Facebook
            'sptfy.com',     # Spotify
            'trib.al',       # Various media
            'spr.ly',        # Social / marketing
            'lnkd.in',       # LinkedIn (already included above)

            # Marketing / analytics shorteners
            'rebrand.ly',
            'smarturl.it',
            'dlvr.it',
            'hubs.ly',
            'ctt.ec', 'ctt.ac',   # ClickToTweet
            'snip.ly',
            'bit.do',

            # Older / legacy but still seen
            'cli.gs',
            'su.pr',
            'tr.im',
            'j.mp',
            'u.to',
            'v.gd',
            'tiny.pl',

            # Questionable / frequently abused services
            'bc.vc',
            'sh.st',
            'adfoc.us',
            'linkbucks.com',
            'shorturl.at',
            'short.cm',
            't2m.io',

            # Region- / niche-specific shorteners
            'goo.gl',      # (legacy, but still present in older phish)
            'x.co',
            'wp.me',       # WordPress
            'rb.gy',
            'bitly.is',
        }

        if any(shortener in body for shortener in shorteners):
            score += 15

        # ===== 9. LEGITIMATE INDICATORS REDUCE SCORE =====
        legit_indicators = {
            # Standard footer / compliance language
            'unsubscribe',
            'manage preferences',
            'email preferences',
            'update your preferences',
            'opt out',
            'opt-out',
            'you are receiving this email because',
            'if you no longer wish to receive',
            'stop receiving these emails',

            # Legal / policy links
            'privacy policy',
            'cookie policy',
            'terms of service',
            'terms & conditions',
            'terms and conditions',
            'legal notice',
            'imprint',
            'data protection',

            # Contact / support wording
            'contact us',
            'contact support',
            'customer service',
            'customer support',
            'support center',
            'help center',
            'help & support',
            'faq',
            'frequently asked questions',

            # Company identity / address (often in legitimate marketing)
            'all rights reserved',
            '©',  # copyright symbol in footer
            'registered office',
            'mailing address',
            'business address',

            # Preference / account management links
            'view this email in your browser',
            'view online version',
            'add us to your address book',
            'why did i get this?',
            'manage your subscription',
            'email settings',
        }

        legit_count = sum(1 for indicator in legit_indicators if indicator in body)
        
        if legit_count >= 3:
            score = int(score * 0.6)  # 40% reduction
        elif legit_count >= 2:
            score = int(score * 0.7)  # 30% reduction

        # ===== 10. TRUST LEVEL ADJUSTMENT =====
        trust_level = self._get_trust_level(sender_domain)
        if trust_level == 'high':
            score = int(score * 0.5)  # 50% reduction
        elif trust_level == 'medium':
            score = int(score * 0.75)  # 25% reduction
            
        analysis_data['heuristic_indicators'] = indicators
        return min(score, 100)
    
    def _check_sender_mismatch(self, analysis_data: Dict) -> bool:
        """Check if sender display name doesn't match email domain"""
        sender = analysis_data.get('sender', '')
        if '<' in sender and '>' in sender:
            try:
                display_name = sender.split('<')[0].strip().lower()
                email_address = sender.split('<')[1].split('>')[0].lower()
                
                for brand in self.brand_domains.keys():
                    if brand in display_name and brand not in email_address:
                        return True
            except:
                pass
        return False
    
    def _determine_verdict(self, risk_score: int) -> str:
        if risk_score >= self.thresholds['malicious']:
            return "MALICIOUS"
        elif risk_score >= self.thresholds['suspicious']:
            return "SUSPICIOUS"
        else:
            return "CLEAN"