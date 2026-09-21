/**
 * ---------------------------------------------------------------------------
 * routes/policy.routes.js - Acceptable Use Policy and legal disclosures.
 * ---------------------------------------------------------------------------
 * These endpoints serve the policy text the client renders in the modal the user
 * must accept before signing in, plus a machine-readable summary of what the
 * moderation engine enforces.
 *
 * Two audiences are served deliberately:
 *  - The USER, who needs plain-language rules. Clarity here is what makes the
 *    policy enforceable; a user cannot be held to a rule they could not read.
 *  - The OPERATOR, who needs a citable inventory of the legal basis behind each
 *    category, which is what a regulator will ask for.
 */

import { Router } from 'express';
import { KEYWORD_CATEGORIES, ACTION } from '../moderation/keywords.js';
import { CRISIS_RESOURCES } from '../moderation/engine.js';

const router = Router();

/**
 * GET /api/policy/acceptable-use
 * The Acceptable Use Policy the user must accept before signing in.
 */
router.get('/acceptable-use', (req, res) => {
  res.json({
    ok: true,
    version: '2.0',
    updated: '2026-01-01',
    summary:
      'LifelineSMS exists so people in the Philippines can reach family who only '
      + 'receive standard SMS. It may not be used to break the law, harm anyone, or '
      + 'send bulk or commercial messages.',

    prohibited: [
      {
        id: 'drugs_and_substances',
        title: 'Illegal drugs',
        detail: 'Buying, selling, arranging delivery of, or coordinating the use of '
          + 'any dangerous drug.',
        statute: 'RA 9165 - Comprehensive Dangerous Drugs Act of 2002',
      },
      {
        id: 'kidnapping_and_detention',
        title: 'Kidnapping and illegal detention',
        detail: 'Abducting or detaining anyone, demanding ransom, or planning a '
          + 'carnapping or hijacking.',
        statute: 'Revised Penal Code Art. 267-268',
      },
      {
        id: 'child_exploitation',
        title: 'Child exploitation',
        detail: 'Any sexual content involving minors, or arranging contact with a '
          + 'child for sexual purposes. This is reported to the authorities.',
        statute: 'RA 9775 Anti-Child Pornography Act / RA 7610',
      },
      {
        id: 'trafficking',
        title: 'Human trafficking',
        detail: 'Recruiting, transporting or selling people, or arranging '
          + 'prostitution or deceptive overseas work.',
        statute: 'RA 9208 as amended by RA 10364',
      },
      {
        id: 'illegal_abortion',
        title: 'Illegal abortion',
        detail: 'Arranging, advertising or supplying a means of terminating a '
          + 'pregnancy outside the law.',
        statute: 'Revised Penal Code Art. 256-259',
      },
      {
        id: 'weapons_and_explosives',
        title: 'Illegal firearms and explosives',
        detail: 'Buying, selling, smuggling or manufacturing unlicensed firearms, '
          + 'ammunition or explosives.',
        statute: 'RA 10591 / RA 9516',
      },
      {
        id: 'terrorism',
        title: 'Terrorism',
        detail: 'Threatening, planning or supporting violent attacks, or recruiting '
          + 'for an armed group.',
        statute: 'RA 11479 - Anti-Terrorism Act of 2020',
      },
      {
        id: 'violence_and_threats',
        title: 'Violence and threats',
        detail: 'Threatening or arranging to kill, injure, or extort anyone.',
        statute: 'Revised Penal Code / RA 10175 Grave Threats',
      },
      {
        id: 'fraud_and_scams',
        title: 'Fraud and scams',
        detail: 'Phishing, prize scams, impersonating an agency or bank, stealing '
          + 'one-time PINs, or soliciting account details.',
        statute: 'RA 10175 Cybercrime Prevention Act / RA 8484',
      },
      {
        id: 'illegal_trade',
        title: 'Smuggling, corruption and illegal trade',
        detail: 'Smuggling, dealing in stolen goods, forged documents, buying '
          + 'votes, or offering or accepting bribes.',
        statute: 'RA 3019 / RA 10863 / Revised Penal Code',
      },
      {
        id: 'sexual_exploitation',
        title: 'Sexual exploitation and harassment',
        detail: 'Selling or soliciting sexual services, sharing intimate images '
          + 'without consent, or sexual harassment.',
        statute: 'RA 11313 Safe Spaces Act / RA 9262 / RA 9995',
      },
      {
        id: 'gambling',
        title: 'Illegal gambling',
        detail: 'Operating or placing bets with an unlicensed numbers game, '
          + 'cockfight or online casino.',
        statute: 'PD 1602 / RA 9287',
      },
      {
        id: 'bulk_and_commercial',
        title: 'Bulk, commercial and political messaging',
        detail: 'Broadcasting, spamming, chain letters, lending promotions or '
          + 'campaign material. This is an emergency channel, not a marketing one.',
        statute: 'RA 10175 Sec. 4(c)(3) / COMELEC Res. 11130',
      },
    ],

    // Crisis content is explicitly NOT prohibited. Stated plainly so a user in
    // distress is not deterred from sending the message that reaches their family.
    alwaysAllowed: [
      {
        id: 'crisis_support',
        title: 'Messages about your own distress are always delivered',
        detail:
          'If you write that you are struggling, thinking about suicide or self-harm, '
          + 'your message is still sent. It does not use up your allowance and it is not '
          + 'treated as a violation. We will also show you free, 24/7 support numbers '
          + 'and offer to alert someone you trust.',
      },
      {
        id: 'family_emergency',
        title: 'Ordinary family and emergency messages',
        detail: 'Reaching a relative, asking for help, reporting your location, or '
          + 'letting someone know you are safe.',
      },
    ],

    enforcement: {
      process: [
        'Messages are checked automatically before they are sent.',
        'A message that appears to involve illegal activity is refused and recorded.',
        'Every decision is written to a tamper-evident audit log.',
        'Repeated attempts to send prohibited content flag the account for review.',
        'Content involving the sexual exploitation of children is reported to the authorities.',
      ],
      dataHandling:
        'Message contents are never stored. Only a salted hash and the categories that '
        + 'were triggered are recorded, so the log can prove what happened without '
        + 'becoming a database of private conversations.',
      appeals:
        'If you believe a message was refused in error, contact support with the '
        + 'approximate time. The audit record for that attempt can be reviewed.',
    },

    contact: {
      support: 'support@lifelinesms.example',
      privacy: 'privacy@lifelinesms.example',
    },
  });
});

/**
 * GET /api/policy/categories
 * Machine-readable inventory of enforced categories with their legal basis.
 * Intended for compliance review, not for the end user.
 */
router.get('/categories', (req, res) => {
  const categories = KEYWORD_CATEGORIES.map((category) => ({
    id: category.id,
    label: category.label,
    action: category.action ?? ACTION.BLOCK,
    // Stated explicitly so an auditor can confirm crisis content is never
    // blocked by policy.
    blocksDelivery: (category.action ?? ACTION.BLOCK) === ACTION.BLOCK,
    severityWeight: category.weight,
    contextGated: Boolean(category.requiresContext),
    statute: category.statute,
    termCount: category.terms.length,
  }));

  res.json({
    ok: true,
    categories,
    totals: {
      categories: categories.length,
      terms: categories.reduce((sum, category) => sum + category.termCount, 0),
      enforcing: categories.filter((category) => category.blocksDelivery).length,
      crisisAssist: categories.filter((category) => !category.blocksDelivery).length,
    },
  });
});

/**
 * GET /api/policy/crisis-resources
 * Support resources surfaced on the crisis path.
 *
 * Kept public and unauthenticated on purpose: if someone reaches this page in
 * distress before signing in, the numbers must be available without a login.
 */
router.get('/crisis-resources', (req, res) => {
  res.json({
    ok: true,
    resources: CRISIS_RESOURCES,
    note: 'These lines are free and available 24/7. If you are in immediate danger, call 911.',
  });
});

export default router;
