# Penlock screens

Every screen of the app, captured from the KeyOS simulator at 480×800. All data is a public test phrase.
The grey camera area stands in for the live camera picture, and the read states in 13, 14, 15, 17 and 18 were
staged, since reaching them needs paper strips. Colours are corrected: the driver's raw screenshots swap red and blue.

| Files | Flow |
| --- | --- |
| 01 | Seed warning popup, shown on every launch |
| 02 | Home: the four choices |
| 03–07 | Enter a phrase: empty, keyboard, unknown word, failed checksum, valid |
| 08–11 | The three shares to copy, and the grid scrolled |
| 12–15 | Restore: scanning, one strip read, recovered with the phrase hidden and shown |
| 16–18 | Read a written phrase: scanning, words read, review against the paper |
| 19–21 | MuSig wallet: choose a key source, paste a share (simulator only), no cosigners yet |
| 22–24 | Show my key, cosigner added, wallet ready |
| 25–26 | Receive addresses |
| 27–30 | Signing: review, round 1, partial signature, final transaction |
| 31 | Error message |
| 32 | Home with a wallet open |
| 33 | Scan a QR code, in the app |

Built with the Prime Kit design system (dark theme). Differences from the Penlock redesign canvas:

- The camera view is a full-width square, because the camera draws a fixed 480 × 480 picture.
- "Sign with share N" stays disabled until all three shares are viewed, because it clears the others.
- The paste screen's buttons sit under the field, because the keyboard covers the bottom of the screen.
- The review headline is 56px rather than 64px, so long amounts stay on screen.
- Outlines that are dashed on the canvas are solid here.
