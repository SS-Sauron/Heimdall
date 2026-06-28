---
name: The Oracle
colors:
  surface: '#131313'
  surface-dim: '#131313'
  surface-bright: '#3a3939'
  surface-container-lowest: '#0e0e0e'
  surface-container-low: '#1c1b1b'
  surface-container: '#201f1f'
  surface-container-high: '#2a2a2a'
  surface-container-highest: '#353534'
  on-surface: '#e5e2e1'
  on-surface-variant: '#d0c5af'
  inverse-surface: '#e5e2e1'
  inverse-on-surface: '#313030'
  outline: '#99907c'
  outline-variant: '#4d4635'
  surface-tint: '#e9c349'
  primary: '#f2ca50'
  on-primary: '#3c2f00'
  primary-container: '#d4af37'
  on-primary-container: '#554300'
  inverse-primary: '#735c00'
  secondary: '#c5c7c8'
  on-secondary: '#2e3132'
  secondary-container: '#494c4d'
  on-secondary-container: '#babcbd'
  tertiary: '#d0cdcd'
  on-tertiary: '#313030'
  tertiary-container: '#b4b2b2'
  on-tertiary-container: '#454544'
  error: '#ffb4ab'
  on-error: '#690005'
  error-container: '#93000a'
  on-error-container: '#ffdad6'
  primary-fixed: '#ffe088'
  primary-fixed-dim: '#e9c349'
  on-primary-fixed: '#241a00'
  on-primary-fixed-variant: '#574500'
  secondary-fixed: '#e1e3e4'
  secondary-fixed-dim: '#c5c7c8'
  on-secondary-fixed: '#191c1d'
  on-secondary-fixed-variant: '#454748'
  tertiary-fixed: '#e5e2e1'
  tertiary-fixed-dim: '#c8c6c5'
  on-tertiary-fixed: '#1c1b1b'
  on-tertiary-fixed-variant: '#474746'
  background: '#131313'
  on-background: '#e5e2e1'
  surface-variant: '#353534'
  oracle-gold: '#D4AF37'
  void-black: '#050505'
  tower-grey: '#2D2D2D'
  hazard-red: '#FF4B2B'
  ethereal-blue: '#00D1FF'
typography:
  headline-lg:
    fontFamily: Newsreader
    fontSize: 40px
    fontWeight: '600'
    lineHeight: '1.2'
    letterSpacing: -0.02em
  headline-lg-mobile:
    fontFamily: Newsreader
    fontSize: 32px
    fontWeight: '600'
    lineHeight: '1.2'
  headline-md:
    fontFamily: Newsreader
    fontSize: 24px
    fontWeight: '500'
    lineHeight: '1.4'
  body-md:
    fontFamily: Inter
    fontSize: 16px
    fontWeight: '400'
    lineHeight: '1.6'
  label-caps:
    fontFamily: JetBrains Mono
    fontSize: 12px
    fontWeight: '500'
    lineHeight: '1'
    letterSpacing: 0.1em
  code-sm:
    fontFamily: JetBrains Mono
    fontSize: 13px
    fontWeight: '400'
    lineHeight: '1.5'
spacing:
  unit: 4px
  gutter: 24px
  margin-mobile: 16px
  margin-desktop: 64px
  container-max: 1200px
---

## Brand & Style

The design system adopts a direction titled **"The Oracle,"** a high-contrast, technical aesthetic that blends the precision of cybersecurity with the occult symbolism of Tarot. The brand personality is authoritative, watchful, and uncompromising. It moves away from generic "hacker" neon toward a "digital hermeticism"—where security is treated as both a technical necessity and a ritualistic guarding of the gates.

The visual style is a fusion of **Minimalism** and **Modern Corporate**, punctuated by mythic flourishes. It utilizes stark monochrome surfaces to represent the void, while gold accents symbolize the "divine light" of system awareness and monitoring. The emotional response is one of calm vigilance; the user should feel like the overseer of an impenetrable fortress, aided by an all-seeing eye.

## Colors

The palette is strictly governed by the "The Tower" tarot influence, favoring deep blacks and brilliant golds.

*   **Primary (Oracle Gold):** Reserved for critical security status, active monitoring indicators, and primary calls to action. It represents illumination and value.
*   **Neutral (Void Black & Tower Grey):** The background is a near-pure black (`#050505`), creating a sense of infinite depth. Surfaces and cards use a layered hierarchy of `tower-grey` to establish structure.
*   **Secondary (Ethereal White):** Used for primary body text to ensure maximum legibility against the dark void.
*   **Functional Colors:** Red is used sparingly for system breaches or critical errors, while `ethereal-blue` provides a subtle technical secondary accent for non-critical data visualization.

## Typography

This design system employs a "Mythic-Technical" typographic pairing.

*   **Headlines (Newsreader):** A sophisticated serif that evokes the feeling of an ancient manuscript or a literary text. This font is used for page titles and section headers to ground the technical portal in the "Oracle" narrative.
*   **Body (Inter):** A neutral, highly legible sans-serif for settings, descriptions, and general UI controls.
*   **Technical Labels (JetBrains Mono):** Monospaced type is used for all data inputs, status readouts, and metadata. This reinforces the cybersecurity nature of the tool, signaling that these elements are "machine-readable" and precise. Labels should frequently use the `label-caps` style for a structural, architectural feel.

## Layout & Spacing

The layout philosophy follows a **Fixed Grid** model for centralized configuration cards, but allows for **Fluid** width for data-heavy monitoring dashboards.

*   **Rhythm:** An 8px base grid is used for all spatial relationships.
*   **Structure:** Elements are housed in "monolith" containers. In the setup portal, the main configuration interface is centered with a max-width of 600px to maintain focus.
*   **Responsive Behavior:** 
    *   **Desktop:** Large horizontal margins (64px+) to emphasize the "Oracle" eye in the center of the void.
    *   **Tablet:** Gutters shrink to 24px, and card widths expand to fill the screen.
    *   **Mobile:** 16px safe-area margins. Complex data tables reflow into single-column vertical lists.

## Elevation & Depth

Hierarchy is established through **Tonal Layers** rather than traditional shadows, mimicking the "The Tower" card's flat but stacked composition.

*   **Surface Hierarchy:** The base level is `void-black`. Containers sit one level above in `tower-grey`. 
*   **Low-Contrast Outlines:** Instead of shadows, surfaces are defined by subtle 1px borders in a muted gold or dark grey (`#2D2D2D`). This creates a "blueprint" feel.
*   **Oracle Glow:** A primary elevation technique involves a very soft, centered gold radial gradient (`primary_color_hex` at 5% opacity) behind the main active container, simulating the aura of the "all-seeing eye."
*   **Glassmorphism:** Used exclusively for overlaying "The Tower" icon or tarot-inspired illustrations, using a heavy backdrop blur (20px) to keep the focus on the foreground data.

## Shapes

The shape language is **Sharp (0)**. 

To reflect the "The Citadel" and "The Tower" influences, all UI elements—including buttons, input fields, and cards—utilize 90-degree corners. This evokes architectural masonry and technical precision. Circular shapes are reserved strictly for "The Eye" symbol and status LEDs, creating a deliberate visual contrast between the "Organic/Divine" (the monitor) and the "Structured/Technical" (the system).

## Components

*   **Buttons:** Rectangular with no radius. Primary buttons are solid `oracle-gold` with black text. Secondary buttons are outlined in white. All buttons use a "hover lift" animation where a thin gold line appears 4px above the button.
*   **Input Fields:** Ghost-style inputs with only a bottom border of 1px. Labels sit above in `label-caps` JetBrains Mono. Focus state triggers a vertical gold bar on the left edge.
*   **Cards:** Thick 2px borders on the top and bottom, with no borders on the left or right, creating a sense of an infinite technical scroll.
*   **Chips/Badges:** Monospaced text inside a simple 1px gold frame. Used for port numbers and active protocols.
*   **Custom Icons:** Inspired by Tarot iconography. The "Scan" icon is a stylized Eye; the "Security/Lock" icon is a vertical stone tower; "Error" is represented by a lightning bolt striking a line. Use `1.5px` stroke weight for all icons.
*   **The Progress Bar:** A thin, segmented line reminiscent of a labyrinth path, filling with gold as the setup completes.