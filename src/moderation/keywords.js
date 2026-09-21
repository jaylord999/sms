/**
 * ---------------------------------------------------------------------------
 * moderation/keywords.js - Categorised prohibited-content blocklist.
 * ---------------------------------------------------------------------------
 * DESIGN NOTES
 *  - Every term is lowercase and in its *normalised* form (no leet, no
 *    separators), because normalize.js already de-obfuscates the input.
 *  - `weight` contributes to the cumulative severity score (0-100).
 *  - `hard` terms are auto-blocked regardless of context (e.g. CSAM).
 *  - `requiresContext` terms only fire when a co-occurring term from
 *    `contextHints` is present. This prevents brutal false positives:
 *    "abort the download" must NOT be flagged, "abort the pregnancy" must.
 *
 * LEGAL BASIS (Philippines)
 *  - RA 9165  Comprehensive Dangerous Drugs Act
 *  - RA 9208 / RA 10364 Anti-Trafficking in Persons Act
 *  - RA 7610  Special Protection of Children Against Abuse / Exploitation
 *  - RA 9775  Anti-Child Pornography Act
 *  - RA 11934 SIM Registration Act
 *  - RA 10175 Cybercrime Prevention Act
 *  - RA 10591 Comprehensive Firearms and Ammunition Regulation Act
 *  - RA 11479 Anti-Terrorism Act
 *  - Act No. 3815 Revised Penal Code (kidnapping, abortion, homicide)
 *  - RA 11313 Safe Spaces Act / RA 9262 VAWC / RA 11036 Mental Health Act
 *  - PD 1602 Illegal Numbers Game / RA 9287 Illegal Cockfighting
 *
 * NOT LEGAL ADVICE. Obtain review from qualified PH counsel before launch.
 */

/**
 * @typedef {Object} KeywordCategory
 * @property {string} id           Machine-readable category key.
 * @property {string} label        Human-readable label shown in the UI.
 * @property {number} weight       Base severity contribution (0-100).
 * @property {string} statute      Primary PH legal reference.
 * @property {string[]} terms      Normalised lowercase terms.
 * @property {string[]} [contextHints] Co-occurring terms that unlock matching.
 * @property {boolean} [requiresContext]
 * @property {boolean} [hard]      Unconditional block, no scoring.
 */

/** @type {KeywordCategory[]} */
export const KEYWORD_CATEGORIES = [
  {
    id: 'drugs',
    label: 'Illegal Drugs (RA 9165)',
    weight: 78,
    statute: 'RA 9165 - Comprehensive Dangerous Drugs Act of 2002',
    hard: false,
    terms: [
      'shabu', 'methamphetamine', 'methamfetamine', 'crystal meth', 'cocaine',
      'cocain', 'heroin', 'ecstasy', 'mdma', 'lsd', 'ketamine', 'fentanyl',
      'opium', 'marijuana', 'marihuana', 'cannabis', 'hashish', 'ganja',
      'kush', 'party drug', 'designer drug', 'drug deal', 'drug dealer',
      'drug den', 'drug pusher', 'buy drugs', 'sell drugs', 'score drugs',
      'get high', 'drug lab', 'meth lab', 'cook meth', 'precursor chemical',
      'pseudoephedrine', 'ephedrine', 'safrole', 'yaba', 'droga',
      'gamot illegal', 'may shabu', 'benta shabu', 'shabu tayo',
    ],
  },
  {
    id: 'abortion',
    label: 'Illegal Abortion (RPC Art. 256-259)',
    weight: 74,
    statute: 'Revised Penal Code Art. 256-259 - Intentional/Unintentional Abortion',
    requiresContext: true,
    // Hints that disambiguate criminal intent from ordinary usage.
    contextHints: [
      'abort', 'abortion', 'abortifacient', 'terminate', 'termination',
      'pregnancy', 'pregnant', 'baby', 'fetus', 'foetus', 'unborn',
      'curettage', 'misoprostol', 'cytotec', 'mifepristone', 'ru486',
      'back alley', 'hilot', 'pampalaglag', 'ipapalaglag', 'palaglag',
    ],
    terms: [
      'back alley abortion', 'abortion pill', 'abortion drug',
      'self induced abortion', 'home abortion', 'cheap abortion',
      'pampalaglag', 'ipapalaglag', 'magpalaglag', 'palaglag',
      'pamparegla', 'abortifacient', 'misoprostol buy', 'cytotec buy',
      'buy cytotec', 'buy misoprostol', 'ru486 buy', 'abortionist',
      'illegal abortion', 'underground abortion', 'abortion service',
      'abortion package', 'abortion kit', 'herbal abortion',
      'gamot pampalaglag', 'sangkap pampalaglag',
    ],
  },
  {
    id: 'kidnapping',
    label: 'Kidnapping / Illegal Detention (RPC Art. 267-268)',
    weight: 92,
    statute: 'Revised Penal Code Art. 267-268 - Kidnapping and Serious Illegal Detention',
    hard: false,
    terms: [
      'kidnap', 'kidnapping', 'kidnaper', 'kidnapper', 'abduct', 'abduction',
      'snatch child', 'snatching child', 'hostage', 'hostage taking',
      'hold hostage', 'ransom', 'illegal detention', 'grab the child',
      'take the child', 'carnap', 'carnapping', 'carjack', 'carjacking',
      'hijack', 'hijacking', 'dukot', 'nakaw bata', 'agaw bata',
      'agawin ang bata', 'kidnap for ransom', 'shanghai',
      'force into van', 'throw in the trunk', 'trunk the body',
    ],
  },
  {
    id: 'csam',
    label: 'Child Sexual Abuse Material (RA 9775 / RA 7610)',
    weight: 100,
    statute: 'RA 9775 Anti-Child Pornography Act / RA 7610 Child Abuse',
    hard: true,
    terms: [
      'child porn', 'childporn', 'child pornography', 'cp link',
      'minor nudes', 'underage nudes', 'underage sex', 'kiddie porn',
      'pedo', 'pedophile', 'pedophilia', 'lolicon', 'shotacon', 'jailbait',
      'child sex', 'child nude', 'child naked', 'preteen nude',
      'preteen sex', 'toddler nude', 'molest child', 'grooming minor',
      'groom the kid', 'child exploitation', 'csam',
      'child trafficking material', 'bata hubad', 'batang hubad',
      'hubad na bata', 'bastos na bata',
    ],
  },
  {
    id: 'trafficking',
    label: 'Human Trafficking (RA 9208 as amended by RA 10364)',
    weight: 95,
    statute: 'RA 9208 / RA 10364 - Anti-Trafficking in Persons Act',
    hard: false,
    terms: [
      'human trafficking', 'trafficking', 'trafficker', 'sex trafficking',
      'sex slave', 'sex worker recruit', 'recruit girls', 'recruit women',
      'buy a girl', 'buy a woman', 'sell a girl', 'sell a woman',
      'mail order bride', 'cybersex den', 'cybersex operation',
      'webcam girl operation', 'escort recruit', 'pimp', 'pimping',
      'prostitution ring', 'brothel', 'illegal recruitment abroad',
      'work abroad no papers', 'fake job offer abroad', 'debt bondage',
      'forced labor', 'labor trafficking',
    ],
  },
  {
    id: 'weapons',
    label: 'Illegal Firearms & Explosives (RA 10591 / RA 9516)',
    weight: 80,
    statute: 'RA 10591 Firearms Regulation / RA 9516 Illegal Explosives',
    requiresContext: true,
    contextHints: [
      'buy', 'sell', 'order', 'acquire', 'ship', 'deliver', 'untraceable',
      'unlicensed', 'no license', 'illegal', 'homemade', 'assemble', 'build',
      'smuggle', 'price', 'how much', 'contact', 'supplier', 'source',
    ],
    terms: [
      'buy gun', 'buy firearm', 'buy pistol', 'buy rifle', 'unlicensed gun',
      'unlicensed firearm', 'illegal firearm', 'untraceable gun',
      'ghost gun', 'homemade gun', '3d printed gun', 'printed firearm',
      'assault rifle', 'ar15 buy', 'illegal na baril', 'loose firearm',
      'gun running', 'gunrunner', 'arms dealer', 'arms trafficking',
      'bomb making', 'pipe bomb', 'improvised explosive', 'make a bomb',
      'bomb recipe', 'explosive recipe', 'detonator', 'grenade buy',
      'ammunition buy', 'ammo buy', 'tnt buy', 'how to make explosives',
      'molotov recipe', 'pusil',
    ],
  },
  {
    id: 'terrorism',
    label: 'Terrorism & Violent Extremism (RA 11479)',
    weight: 98,
    statute: 'RA 11479 - Anti-Terrorism Act of 2020',
    hard: false,
    terms: [
      'terrorist', 'terrorist attack', 'join isis', 'join jihad',
      'join terrorist', 'isis recruit', 'extremist recruit',
      'bomb a building', 'bomb the mall', 'bomb the church', 'blow up the',
      'mass shooting plan', 'shoot up the', 'lone wolf attack',
      'martyrdom operation', 'suicide bombing', 'behead',
      'beheading video', 'execute the hostage', 'overthrow the government',
      'armed revolution', 'radicalize', 'attack plan', 'target list kill',
    ],
  },
  {
    id: 'violence',
    label: 'Violence, Murder & Injury (Revised Penal Code)',
    weight: 85,
    statute: 'Revised Penal Code - Murder, Homicide, Physical Injuries',
    hard: false,
    terms: [
      'kill him', 'kill her', 'kill them', 'kill you', 'kill u',
      'murder him', 'murder her', 'murder for hire', 'hitman',
      'contract killing', 'assassinate', 'assassination', 'i will kill',
      'ill kill', 'gonna kill', 'going to kill', 'stab him', 'stab her',
      'shoot him', 'shoot her', 'slit throat', 'strangle him',
      'strangle her', 'smother him', 'poison him', 'poison her',
      'beat him up', 'beat her up', 'break his legs', 'break her legs',
      'put a hit', 'send a hitman', 'dispose the body', 'hide the body',
      'bury the body', 'papatayin', 'ipapatay', 'patayin mo',
      'sasaktan kita', 'ipahamak', 'bugbog', 'barilin', 'saksakin',
      'lasunin', 'kill list',
    ],
  },
  {
    // =========================================================================
    // POLICY: CRISIS SUPPORT - NOT ENFORCEMENT.
    //
    // Self-harm and suicidal ideation content is deliberately placed in its own
    // category with `assistOnly: true` and `action: 'assist'`.
    //
    // WHY WE DO NOT BLOCK THESE MESSAGES:
    //  1. Blocking a crisis message is a duty-of-care failure. If a distressed
    //     user is refused service and is then harmed, the platform operator
    //     carries real civil and moral liability - precisely the outcome this
    //     filter exists to prevent.
    //  2. The product promise is "reach family in an emergency." For a person
    //     in crisis, the outgoing message IS the emergency.
    //  3. RA 11036 (Philippine Mental Health Act) frames the obligation as
    //     providing access to care and support, not as censorship.
    //  4. A blocked ""I want to die"" teaches the user the system will not help
    //     them, and they will not try again.
    //
    // WHAT THE PLATFORM DOES INSTEAD:
    //  - The message IS DELIVERED, normally and immediately.
    //  - Crisis resources are surfaced (NCMH 1553, Hopeline 2919, 911).
    //  - The user is offered an opt-in ""alert a trusted contact"" action.
    //  - The send does NOT consume a message credit and is NOT treated as abuse.
    //  - A `crisis_support_offered` event is recorded as evidence of care.
    // =========================================================================
    id: 'self_harm_crisis',
    label: 'Crisis Support Required - Not Blocked (RA 11036 Mental Health Act)',
    weight: 88,
    statute: 'RA 11036 - Philippine Mental Health Act (duty of care, not censorship)',
    action: 'assist',
    assistOnly: true,
    hard: false,
    terms: [
      // --- English: explicit intent ---
      'kill myself', 'killing myself', 'killing my self', 'end my life',
      'ending my life', 'end it all', 'commit suicide', 'committing suicide',
      'suicide plan', 'suicide method', 'suicide note', 'take my own life',
      'take my life', 'want to die', 'wanna die', 'wanted to die',
      'i want to die', 'i wanna die', 'going to kill myself',
      'how to kill myself', 'better off dead', 'no reason to live',
      'nothing to live for', 'cant go on', 'cannot go on', 'give up on life',
      'not worth living', 'tired of living', 'no way out', 'no hope left',
      // --- English: method signals (still delivered, still assisted) ---
      'cut myself', 'cutting myself', 'hurt myself', 'hurting myself',
      'self harm', 'selfharm', 'overdose myself', 'hang myself',
      'jump off the bridge', 'slit my wrist', 'slit my wrists',
      'swallow pills', 'swallowed pills', 'end my suffering',
      'goodbye everyone', 'goodbye world', 'this is my last message',
      'final message', 'final goodbye', 'i wont be here tomorrow',
      // --- English: hopelessness (lighter, still assist) ---
      'nobody would miss me', 'everyone is better off without me',
      'i am a burden', 'im a burden', 'tired of everything',
      'i cant take it anymore', 'i want it to stop',
      // --- Filipino / Tagalog: explicit intent ---
      'magpapakamatay', 'magpapakamatay ako', 'magpapakamatay na ako',
      'papakamatay', 'papakamatay ako', 'magpatiwakal',
      'gusto kong mamatay', 'gusto ko nang mamatay', 'gusto ko mamatay',
      'gusto ko na mamatay', 'gusto ko nang mawala',
      'gusto ko nang mamatay na', 'ayaw ko nang mabuhay',
      'ayaw ko na mabuhay', 'ayaw ko na po mabuhay',
      'pagod na ako mabuhay', 'sawa na ako mabuhay',
      'wala nang saysay buhay ko', 'wala nang dahilan mabuhay',
      'wala nang saysay ang buhay ko', 'walang saysay buhay ko',
      'tapusin na ang lahat', 'tapusin ko na buhay ko',
      'tatapusin ko na', 'tatapusin ko na buhay ko',
      'tatapusin ko na ang buhay ko', 'wala nang pag asa',
      'wala nang pag-asa', 'pabigat lang ako', 'pabigat ako sa inyo',
      'hindi na ako mahalaga', 'wala akong halaga',
      // --- Filipino: final-goodbye signals ---
      'pasasalamat sa lahat', 'paalam na po sa lahat', 'paalam na ako',
      'paalam mundo', 'huling mensahe ko', 'huling mensahe',
      'hindi na ako bukas', 'wala na ako bukas',
      'magpasalamat ako sa inyo', 'salamat sa lahat',
      // --- Filipino: method signals (still delivered, still assisted) ---
      'susubukan ko magpakamatay', 'magvevenom ako',
      'lalasunin ko sarili ko', 'lalasunin ko ang sarili ko',
      'sasaksakin ko sarili ko', 'gugupitin ko pulso ko',
      'gugupitin ko ang pulso ko', 'tatalon ako sa tulay',
      'tatalon sa building', 'bibigti ako', 'bibigti ko sarili ko',
      'magbibigti', 'magbibitay', 'magbibitay ako',
      'iinom ako ng lason', 'iinum ko lason',
      'gagawin ko na', 'gagawin ko na ang plano',
      // --- Bisaya / Cebuano ---
      'maghikog', 'maghikog ko', 'maghikog nako',
      'gusto nako mamatay', 'gusto na mamatay', 'gusto ko mamatay',
      'dili na ko gusto mabuhi', 'kapoy na kaayo ko',
      'taposon na nako akong kinabuhi', 'tapuson nako tanan',
      'taposon na nako', 'paalam na', 'hikalimot na ko',
      'wa nay pulos akong kinabuhi', 'wa nay paglaum',
      'maglaslas ko', 'magdungag ko', 'manglayat ko',
      'wala na koy paglaum', 'pabug-at ko', 'salamat sa tanan',
    ],
  },
  {
    id: 'fraud_scam',
    label: 'Fraud, Scams & Cybercrime (RA 10175 / RA 8792)',
    weight: 70,
    statute: 'RA 10175 Cybercrime Prevention Act / RA 8792 E-Commerce Act',
    hard: false,
    terms: [
      'phishing', 'phishing link', 'smishing', 'vishing', 'sim swap',
      'steal otp', 'otp steal', 'steal account', 'hack account',
      'crack account', 'credit card dump', 'carding', 'cvv dump', 'fullz',
      'doxx', 'doxing', 'blackmail', 'sextortion', 'i have your nudes',
      'pay or i reveal', 'scam text', 'scam link', 'fake raffle',
      'fake prize', 'claim your prize now', 'ponzi', 'pyramid scheme',
      'double your money', 'guaranteed returns', 'crypto doubling',
      'investment scam', 'loan scam', 'love scam', 'romance scam',
      'advance fee', '419', 'click this link to claim',
      'verify your account here', 'gcash account change',
      'maya account change', 'phishing page', 'keylogger', 'ransom note',
      'encrypt your files', 'bitcoin payment demand',
    ],
  },
  {
    id: 'illegal_trade',
    label: 'Illegal Trade, Smuggling & Corruption',
    weight: 72,
    statute: 'RPC / RA 10863 Customs Modernization / RA 3019 Anti-Graft',
    requiresContext: true,
    contextHints: [
      'buy', 'sell', 'order', 'smuggle', 'ship', 'deliver', 'no receipt',
      'no papers', 'under the table', 'fixer', 'padulas', 'lagay', 'bribe',
      'price', 'how much', 'contact', 'supplier',
    ],
    terms: [
      'smuggle', 'smuggling', 'smuggled goods', 'contraband',
      'illegal logging', 'illegal fishing', 'dynamite fishing',
      'illegal mining', 'wildlife trafficking', 'endangered species sell',
      'buy stolen', 'stolen goods', 'hot items', 'hot cellphone',
      'benta ng nakaw', 'nakaw na gamit', 'fake passport', 'fake id',
      'fake visa', 'fake license', 'fake birth certificate',
      'fake diploma', 'fake nbi', 'bribe', 'bribery', 'lagay', 'padulas',
      'tong', 'fixer', 'kickback', 'human organ sell', 'sell kidney',
      'buy kidney', 'organ trafficking', 'baby for sale', 'sell baby',
      'benta bata', 'benta sanggol',
    ],
  },
  {
    id: 'sexual',
    label: 'Sexual Exploitation & Harassment (RA 11313 / RA 9262)',
    weight: 68,
    statute: 'RA 11313 Safe Spaces Act / RA 9262 VAWC',
    hard: false,
    terms: [
      'send nudes', 'nude pics', 'nudes for sale', 'sexting minor',
      'rape', 'raped you', 'i will rape', 'gang rape', 'sexual assault',
      'molest', 'molestation', 'grope', 'indecent', 'sex for money',
      'sex for hire', 'buy sex', 'hooker', 'cam sex', 'scandal video',
      'sex scandal', 'boso', 'boso video', 'peeping tom', 'upskirt',
      'revenge porn', 'deepfake nude', 'bestiality', 'incest',
      'jav scandal', 'kantot', 'iyot', 'burat', 'jakol', 'malibog',
      'bastos kita', 'libog', 'manyak', 'kalabit',
    ],
  },
  {
    id: 'harassment',
    label: 'Threats, Doxxing & Harassment',
    weight: 66,
    statute: 'RA 10175 Sec. 4(a)(4) / RA 11313 / RA 10627 Anti-Bullying',
    hard: false,
    terms: [
      'i will find you', 'ikaw ang susunod', 'you will regret this',
      'i know where you live', 'i know your address', 'watch your back',
      'gonna hurt you', 'youre dead', 'you are dead', 'death threat',
      'threaten you', 'papatayin kita', 'bibigwasan kita',
      'sasalakayin ko', 'ipapa salvage', 'salvage ka', 'payback time',
      'i will destroy you', 'ruin your life', 'expose your photos',
      'leak your photos', 'post your nudes', 'share your secrets',
    ],
  },
  {
    id: 'gambling',
    label: 'Illegal Gambling (PD 1602 / RA 9287)',
    weight: 60,
    statute: 'PD 1602 Illegal Numbers Game / RA 9287 Illegal Cockfighting',
    requiresContext: true,
    contextHints: [
      'bet', 'betting', 'join', 'play', 'deposit', 'cash in', 'payout',
      'jackpot', 'slot', 'taya', 'taya na', 'swertres', 'lotto',
    ],
    terms: [
      'online casino', 'online sabong', 'esabong', 'jueteng',
      'jueteng bet', 'masiao', 'masiao number', 'last two', 'swertres bet',
      'color game', 'color game bet', 'tongits online', 'pusoy dos bet',
      'cockfight bet', 'sabong match', 'tupada', 'drop ball',
      'basketball betting', 'nba bet', 'fixed fight', 'game fixing',
      'betting site', 'slot machine', 'jackpot site', 'casino deposit',
    ],
  },
  {
    // =========================================================================
    // PHILIPPINE LANGUAGE EXPANSION
    // Tagalog / Taglish / Bisaya (Cebuano) / Ilocano / Hiligaynon / Bicolano.
    // Most PH illegal-SMS traffic is written in Taglish or Bisaya. English-only
    // filters miss the overwhelming majority of real local abuse.
    // Spelling variants are listed separately because SMS users abbreviate
    // heavily and no reliable stemmer exists for these languages.
    // =========================================================================
    id: 'ph_drugs',
    label: 'Illegal Drugs - Filipino/Bisaya (RA 9165)',
    weight: 80,
    statute: 'RA 9165 - Comprehensive Dangerous Drugs Act of 2002',
    hard: false,
    terms: [
      // Tagalog
      'benta shabu', 'may shabu ako', 'shabu tayo', 'shabu dito',
      'hanap shabu', 'saan makakabili shabu', 'shabu presyo',
      'kilo ng shabu', 'isang gramo shabu', 'pakyaw shabu',
      'tulak', 'tulak droga', 'magtutulak', 'tumutulak',
      'gumagamit kami droga', 'droga presyo', 'bilihan droga',
      'party drugs tayo', 'mag weeweed', 'mag jutes', 'mag damo',
      'jutes tayo', 'chongki', 'chongke', 'scoobs', 'kolokoy',
      'rugby tayo', 'mag rugby', 'solvent sniffing', 'glue sniffing',
      'mag ekta', 'ekta', 'tableta droga', 'mag pa tira',
      'shabungan', 'tokhang', 'adik', 'drug adik',
      'retoke droga', 'injection droga', 'saksak droga',
      // Bisaya / Cebuano
      'pamaligya shabu', 'namaligya shabu', 'naay shabu', 'asa palit shabu',
      'shabu baligya', 'mag shabu', 'mo shabu', 'pag shabu',
      'tig baligya shabu', 'durugista', 'mag droga', 'droga baligya',
      'utot drug', 'mag rugby bata', 'suyop rugby', 'kasarangang ',
    ],
  },
  {
    id: 'ph_kidnap',
    label: 'Kidnapping / Pagdukot - Filipino/Bisaya (RPC Art. 267)',
    weight: 94,
    statute: 'Revised Penal Code Art. 267-268 - Kidnapping and Serious Illegal Detention',
    hard: false,
    terms: [
      // Tagalog
      'dukot', 'dudukutin', 'dudukutin ko', 'mag dudukot', 'kidnap ko',
      'agawin', 'agawin ko', 'agawin ang', 'agaw bata', 'agaw bata ko',
      'kunin ang bata', 'kunin natin ang bata', 'samsamin',
      'samsamin ang bata', 'holdapin', 'tangayin', 'tangayin ang bata',
      'ipitin', 'ikulong', 'ikulong mo', 'kulongin', 'kulongin mo',
      'hawakan hostage', 'hawakan ang bata', 'gapusin', 'tanikala',
      'posas', 'posasan', 'ipaposas', 'pantubos', 'tubusan',
      'bayad pantubos', 'dalhin sa van', 'isakay sa van',
      'itapon sa sako', 'ilagay sa sako',
      // Bisaya / Cebuano
      'dukot bata', 'ilogan ang bata', 'kuhiton ang bata',
      'dakpon ang bata', 'hiktan', 'hikti', 'gapus', 'ikulong nako',
      'pantubos kwarta', 'bayri o patyon',
    ],
  },
  {
    id: 'ph_kill',
    label: 'Threats to Kill - Filipino/Bisaya (RPC / RA 10175)',
    weight: 88,
    statute: 'Revised Penal Code - Homicide/Murder; RA 10175 Grave Threats',
    hard: false,
    terms: [
      // Tagalog
      'papatayin ko', 'papatayin kita', 'papatayin ko kayo',
      'papatayin ko siya', 'patayin mo', 'patayin mo siya',
      'ipapatay', 'ipapatay ko', 'ipapatay kita',
      'ipapa salvage', 'salvage ka', 'isasalvage kita',
      'sasaktan kita', 'sasaktan ko', 'sasaktan ko siya',
      'bibigwasan kita', 'bibigwasan ko', 'bugbugin', 'bugbugin ko',
      'sasapakin', 'sasapakin kita', 'susuntukin', 'suntukin kita',
      'sasakalin', 'sasakalin kita', 'sakalin kita', 'lalasunin',
      'lalasunin kita', 'lagyan lason', 'sasaksakin', 'sasaksakin kita',
      'saksakin kita', 'babarilin', 'babarilin kita', 'barilin kita',
      'tatagain', 'tatagain kita', 'putulan ng ulo',
      'putulan kita ulo', 'pugutan', 'pugutan ng ulo',
      'ipapahamak kita', 'ipapahamak ko', 'ipahamak',
      'pagsisihan mo', 'magsisisi ka', 'ikaw ang susunod',
      'gagantihan kita', 'gaganti ako', 'alam ko bahay mo',
      'alam ko tirahan mo', 'alam ko school mo', 'susundan kita',
      'sabotahe', 'siraan kita', 'papahiyain kita', 'durugin kita',
      // Bisaya / Cebuano
      'patyon tika', 'patyon nako', 'patyon tikaw', 'patya',
      'ipapatay tika', 'bun-ogon tika', 'sagpaon', 'sumbagon tika',
      'dugmokon tika', 'hiloan tika', 'labhagan tika',
      'pusilon tika', 'ligsan tika', 'putlan kag ulo', 'pugotan tika',
      'panimalos ko', 'hagiton tika', 'hadlokon tika',
    ],
  },

  {
    id: 'ph_abortion',
    label: 'Illegal Abortion - Filipino/Bisaya (RPC Art. 256)',
    weight: 76,
    statute: 'Revised Penal Code Art. 256-259 - Intentional Abortion',
    requiresContext: true,
    contextHints: [
      'abort', 'palaglag', 'pampalaglag', 'buntis', 'sanggol', 'baby',
      'ipinagbubuntis', 'pregnant', 'pregnancy', 'cytotec', 'misoprostol',
      'hilot', 'masahe', 'regla', 'dinugo', 'ilaglag',
    ],
    terms: [
      // Tagalog
      'pampalaglag', 'pampalaglag baby', 'pampalaglag bata',
      'ipapalaglag', 'ipapalaglag ko', 'magpalaglag', 'magpapalaglag',
      'palaglag', 'ipalaglag', 'ipalaglag ang', 'ipapalaglag natin',
      'gamot pampalaglag', 'gamot palaglag', 'sangkap pampalaglag',
      'pamparegla', 'pamparegla gamot', 'pamparegla update',
      'pampadugo gamot', 'hilot palaglag', 'masahe palaglag',
      'santol pampalaglag', 'papaya pampalaglag', 'makabuhay',
      'magpapabagsak', 'pabagsakin ang tyan', 'pabagsakin tyan',
      'ilaglag ang bata sa tyan', 'alisin ang dinadala',
      'alisin ang bata sa tyan', 'tanggal ang dinadala',
      'tanggalin ang baby', 'paano magpalaglag',
      'saan pwede magpalaglag', 'presyo magpalaglag',
      'magkano magpalaglag', 'abort tayo',
      // Bisaya / Cebuano
      'magpa abort', 'ipa abort', 'pahawaon ang bata sa tiyan',
      'tangtangon ang bata', 'palaglag bata', 'gamot ipalaglag',
      'santol ipalaglag', 'magpa hilot abort', 'iladlad ang bata',
    ],
  },
  {
    id: 'ph_violence',
    label: 'Violence & Extortion - Filipino/Bisaya',
    weight: 82,
    statute: 'RPC - Grave Threats / Robbery / Extortion (Art. 282, 293)',
    hard: false,
    terms: [
      // Tagalog
      'holdap', 'holdapin', 'holdapin kita', 'nakawan', 'nakawan kita',
      'pagnakawan', 'nakaw pera', 'kulitin', 'bayad o sasaktan',
      'bayad o patay', 'bayad o ipapahamak', 'kikilan', 'kikil',
      'kikilan kita', 'kikil pera', 'extortion', 'ibitin', 'sunugin',
      'sunugin bahay', 'sunugin ko bahay', 'sunog bahay', 'tutuyuhin',
      'tutuyuhin bahay', 'bungkalin', 'bungkalin bahay', 'bubuwagin',
      'basagin', 'basagin kotse', 'gasgasan kotse', 'paputukan',
      'paputukan ko', 'guluhin', 'guluhin ko', 'ibabagsak kita',
      'ipapa kulong nang peke', 'siraan reputasyon',
      'siraan kita reputasyon',
      // Bisaya / Cebuano
      'tulis', 'tulison tika', 'ilogan kag kwarta',
      'sunogon ang balay', 'sunogon nako', 'pusilon ang balay',
      'pangguba balay', 'hulga', 'hulgaon tika', 'hulga kwarta',
      'bayad o patyon',
    ],
  },
  {
    id: 'ph_csam',
    label: 'Child Exploitation - Filipino/Bisaya (RA 9775 / RA 7610)',
    weight: 100,
    statute: 'RA 9775 Anti-Child Pornography Act / RA 7610 Child Abuse',
    hard: true,
    terms: [
      // Tagalog
      'bata hubad', 'batang hubad', 'hubad na bata', 'hubad bata',
      'bastos na bata', 'bastos bata', 'malaswang bata',
      'larawan batang hubad', 'pic bata hubad', 'pics bata hubad',
      'video bata hubad', 'bidyo bata hubad', 'ipadala hubad bata',
      'pahubarin ang bata', 'pasuhotin', 'bastusin ang bata',
      'bastusin bata', 'hipuan ang bata', 'hipuan bata', 'kalabit bata',
      'bata para sa sex', 'bata bayaran', 'bayad bata hubad',
      'live stream bata', 'webcam bata hubad', 'bata show',
      'koleksyon bata', 'sanggol hubad', 'anak ko ipapagamit',
      'tito bata', 'groom bata',
      // Bisaya / Cebuano
      'bata hubo', 'hubo nga bata', 'huboa ang bata',
      'bastos nga bata', 'hikuon ang bata', 'bata ipakita hubo',
      'live bata hubo', 'bayran ang bata', 'bata nga hubo pic',
    ],
  },
  {
    id: 'ph_trafficking',
    label: 'Trafficking / Prostitution - Filipino/Bisaya (RA 9208)',
    weight: 95,
    statute: 'RA 9208 / RA 10364 - Anti-Trafficking in Persons Act',
    hard: false,
    terms: [
      // Tagalog
      'bugaw', 'bugaw ako', 'mambubugaw', 'namamato', 'pokpok',
      'pokpok service', 'puta service', 'puta tayo', 'japayuki',
      'gro tayo', 'gro service', 'girls for hire', 'babae for hire',
      'babae bayaran', 'bayad babae', 'escort babae', 'escort service',
      'home service babae', 'home service gro', 'extra service',
      'extra service babae', 'masahe with extra', 'spa extra service',
      'mag aalok babae', 'aalok babae', 'ipapaalok babae',
      'ipapasa ibang lalaki', 'ipapasa babae', 'ilalabas ng bansa',
      'ilalabas abroad', 'ipapadala abroad', 'iabroad nang walang papel',
      'walang papel abroad', 'peke trabaho abroad',
      'illegal recruitment', 'illegal recruiter', 'scam recruitment',
      'sakay barko illegal', 'papeles peke abroad', 'benta katawan',
      'ipagbili ang anak', 'ibenta anak', 'ipagbili ang sarili',
      'benta bata', 'benta sanggol', 'baby for sale', 'sanggol ibenta',
      'ipapamigay bata',
      // Bisaya / Cebuano
      'bugaw ug babae', 'baligya babae', 'babaye bayran',
      'extra service babaye', 'gawas nasod walay papeles',
      'peke nga trabaho', 'baligya bata',
      'hatag bata kapalit kwarta', 'bayran ang bata',
    ],
  },

  {
    id: 'ph_scam',
    label: 'Pinoy Scams & Text Fraud - Filipino/Bisaya (RA 10175)',
    weight: 72,
    statute: 'RA 10175 Cybercrime Act / NPC Advisory on Text Scams',
    hard: false,
    terms: [
      // Tagalog
      'nanalo ka', 'nanalo ka po', 'nanalo ka sa', 'panalo ka',
      'nanalo ka ng premyo', 'premyo mo', 'kunin ang premyo',
      'padala ang bayad para sa premyo', 'manalo sa raffle',
      'swerteng numero', 'claim mo na', 'i claim ang premyo',
      'bayad muna bago claim', 'processing fee muna',
      'delivery fee muna', 'gcash mo ako', 'padala sa gcash',
      'ipadala sa gcash', 'send mo sa gcash ko',
      'palitan ang gcash number', 'gcash password', 'gcash otp',
      'otp mo po', 'ibigay ang otp', 'ipadala ang otp',
      'code mo sa text', 'bigay mo ang code', 'hack gcash',
      'hack fb', 'hack account', 'account mo ma locked',
      'i locked ko account mo', 'may utang ka', 'may kaso ka',
      'warrant of arrest mo', 'nbi ka', 'pulis ka daw',
      'barangay blotter ka', 'loan na approved', 'loan approved click',
      'instant loan click', 'sangla atm', 'sangla titulo',
      '5 6 lending', '5-6 hindi nagbabayad', 'doble ang pera',
      'doble kita', 'siguradong kita', 'crypto double',
      'ponzi tayo', 'padala pera bitcoin', 'usdt padala',
      'usdt double', 'love scam', 'asawa peke',
      'chinese mommy scam', 'foreigner scam',
      // Bisaya / Cebuano
      'nakadaog ka', 'daog ka', 'kwarta padala gcash',
      'padalhi kog kwarta', 'hatagi kog otp', 'ilis gcash number',
      'na hack akong account', 'utang nimo bayri',
      'padala bitcoin', 'doble kwarta',
    ],
  },
  {
    id: 'ph_gambling',
    label: 'Illegal Gambling - Filipino/Bisaya (PD 1602 / RA 9287)',
    weight: 62,
    statute: 'PD 1602 Illegal Numbers Game / RA 9287 Illegal Cockfighting',
    requiresContext: true,
    contextHints: [
      'taya', 'taya na', 'bet', 'deposito', 'cash in', 'payout',
      'swertres', 'lotto', 'jueteng', 'sabong', 'tongits', 'bingo',
    ],
    terms: [
      // Tagalog
      'jueteng taya', 'taya jueteng', 'masiao taya', 'taya masiao',
      'swertres taya', 'taya swertres', 'lotto taya', 'taya ako',
      'taya tayo', 'taya na kayo', 'pustahan', 'pustahan tayo',
      'pusta ako', 'magpupusta', 'sabong tayo', 'manok ko',
      'sabongan', 'sabungan', 'pitasan manok', 'tari manok',
      'tongits tayo', 'tongits online', 'pusoy tayo', 'pusoy dos',
      'bingo tayo', 'drop ball', 'color game taya', 'jai alai taya',
      'pba bet', 'nba bet', 'game fixing', 'luto ang laban',
      'bayad ang referee', 'online casino deposit', 'casino cash in',
      'slot machine taya', 'e sabong', 'esabong', 'efsabong',
      'perya taya', 'last two taya', 'hantak', 'cara y cruz',
      'pula puti taya',
      // Bisaya / Cebuano
      'taya ko', 'manok pusta', 'pusta ta', 'tong its ta',
      'hueteng', 'masiao numero', 'taya kog',
    ],
  },
  {
    id: 'ph_hate',
    label: 'Hate Speech & Harassment - Filipino/Bisaya (RA 11313)',
    weight: 64,
    statute: 'RA 11313 Safe Spaces Act / RA 10627 Anti-Bullying Act',
    hard: false,
    terms: [
      // Tagalog
      'bobo ka', 'tanga ka', 'tanga mo', 'gago ka', 'gaga ka',
      'ulol ka', 'inutil ka', 'walang kwenta ka', 'pakyu',
      'putang ina mo', 'putangina mo', 'putang ina nyo',
      'tangina mo', 'tang ina mo', 'punyeta ka', 'hayop ka',
      'anak ka ng puta', 'bobo mo', 'engot mo', 'tarantado ka',
      'sira ulo mo', 'mamatay ka na', 'sana mawala ka na',
      'dapat wala ka na', 'patay gutom', 'duwag ka', 'pikon ka',
      'sana patay ka na', 'sana hindi ka na ipinanganak',
      'putragis', 'leche ka', 'gago mo', 'ampota',
      // Bisaya / Cebuano
      'buang ka', 'buang kaayo ka', 'bogo ka', 'yawa ka',
      'pisting yawa', 'animal ka', 'boang ka', 'amaw ka',
      'pakyas ka', 'wa kay pulos', 'way ayo ka', 'kigwa ka',
    ],
  },
];

/**
 * Moderation actions. Every detection resolves to exactly one of these.
 * @readonly
 * @enum {string}
 */
export const ACTION = Object.freeze({
  /** Content is acceptable. Deliver normally. */
  ALLOW: 'allow',
  /** Prohibited content. Refuse delivery and record a violation. */
  BLOCK: 'block',
  /**
   * Crisis content. DELIVER the message, then surface support resources and
   * offer to alert a trusted contact. Never refused, never counted as abuse.
   */
  ASSIST: 'assist',
});

/**
 * Terms that are only meaningful in combination with an operational verb, or
 * that legitimately appear in everyday conversation. Kept separate so the
 * engine can apply lighter scoring and avoid blocking normal family SMS.
 *
 * NOTE: these contribute to a score but never independently trigger a block.
 * They exist mainly to raise confidence when combined with a hard category.
 */
export const SOFT_SIGNALS = Object.freeze({
  /** Attempts to move the conversation to a less-monitored channel. */
  contactSolicitation: [
    'dm me', 'pm me', 'text me at', 'contact me at', 'message me on',
    'add me on telegram', 'add me on whatsapp', 'viber me', 'mag text ka',
    'tawagan mo ako', 'mag pm ka', 'hit me up', 'chat mo ako',
    'add mo ako', 'add mo ako sa telegram', 'message mo ako',
  ],
  /** Manufactured urgency, a hallmark of scam and recruitment messages. */
  urgencyBait: [
    'act now', 'limited time', 'hurry up', 'last chance', 'expires today',
    'only today', 'today only', 'claim now', 'click now', 'hurry',
    'bilisan mo', 'ngayon na', 'before it ends', 'mabilis lang',
    'hanggang ngayon lang', 'unahan mo na',
  ],
  /** Commerce phrasing that implies a hand-to-hand transaction. */
  codedCommerce: [
    'benta ko', 'bibili ako', 'may stock ako', 'may delivery', 'cod na',
    'meet up', 'meetup', 'drop off point', 'rider na', 'per piece',
    'per gram', 'kilo price', 'wholesale price', 'may stock',
    'deliver agad', 'sabay tayo', 'kita tayo', 'kita tayo sa',
  ],
  /** Requesting personal identifiers, a strong fraud indicator. */
  identityHarvest: [
    'send your id', 'send mo id mo', 'picture ng id', 'photo ng id',
    'account number mo', 'card number mo', 'cvv mo', 'password mo',
    'birthday mo', 'mothers maiden name', 'full name mo',
    'address mo po', 'asawa mo pangalan', 'anak mo pangalan',
  ],
  /** Money-movement instructions common in scam and extortion texts. */
  paymentPressure: [
    'send money now', 'padala mo na', 'padala na agad', 'bayad na',
    'bayaran mo na', 'transfer na', 'send na sa gcash', 'send na sa maya',
    'iwallet mo', 'bayad muna bago', 'deposito muna', 'downpayment muna',
    'downpayment bago', 'advance payment bago',
  ],
});

/**
 * Flatten every term into a lookup map for fast scanning.
 * @returns {Map<string, {categoryId: string, label: string, weight: number, hard: boolean, requiresContext: boolean, action: string, assistOnly: boolean, statute: string, contextHints: string[]}>}
 */
export function buildTermIndex() {
  /** @type {Map<string, any>} */
  const index = new Map();

  for (const category of KEYWORD_CATEGORIES) {
    const entry = {
      categoryId: category.id,
      label: category.label,
      weight: category.weight,
      hard: Boolean(category.hard),
      requiresContext: Boolean(category.requiresContext),
      action: category.action || ACTION.BLOCK,
      assistOnly: Boolean(category.assistOnly),
      statute: category.statute,
      contextHints: category.contextHints || [],
    };

    for (const term of category.terms) {
      const existing = index.get(term);
      // Assist categories always win: crisis content must never be treated as
      // a violation, even if a term appears on two lists.
      if (existing && existing.assistOnly) continue;
      if (existing && !existing.assistOnly && existing.weight >= entry.weight) continue;
      index.set(term, entry);
    }
  }

  return index;
}

/**
 * Build a flat list of soft-signal phrases for scanning.
 * @returns {Array<{group: string, phrase: string}>}
 */
export function buildSoftSignalList() {
  /** @type {Array<{group: string, phrase: string}>} */
  const list = [];
  for (const [group, phrases] of Object.entries(SOFT_SIGNALS)) {
    for (const phrase of phrases) {
      list.push({ group, phrase });
    }
  }
  return list;
}

export const TERM_INDEX = buildTermIndex();
export const TERM_LIST = Object.freeze([...TERM_INDEX.keys()].sort());
export const SOFT_SIGNAL_LIST = Object.freeze(buildSoftSignalList());

/**
 * Aggregate statistics, used by the startup banner and the admin report.
 * @returns {{categories: number, terms: number, hardCategories: number, assistCategories: number, softSignals: number}}
 */
export function keywordStats() {
  return {
    categories: KEYWORD_CATEGORIES.length,
    terms: TERM_INDEX.size,
    hardCategories: KEYWORD_CATEGORIES.filter((c) => c.hard).length,
    assistCategories: KEYWORD_CATEGORIES.filter((c) => c.assistOnly).length,
    softSignals: SOFT_SIGNAL_LIST.length,
  };
}

export default {
  KEYWORD_CATEGORIES,
  SOFT_SIGNALS,
  ACTION,
  TERM_INDEX,
  TERM_LIST,
  SOFT_SIGNAL_LIST,
  buildTermIndex,
  buildSoftSignalList,
  keywordStats,
};


