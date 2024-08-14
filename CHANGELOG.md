## 2.1

### Features
- Add `n_up` utility to merge images, so shares with many QR code PNGs can be
  merged into fewer PNG images for more convenient distribution.


## 2.0

### BREAKING Changes
- Bump MacHeader version from 1 to 2 and drop support for version 1.
  - Add `payload_size`, 4 byte int field.
  - Shrink `algroithm` field from 24 -> 20 bytes.

### Features
- Add webcam QR code scanner powered by `zbarcam`.
- Support multiple QR codes per input image.
- Accept input from QR code image files and `zbarcam` video feed at the same
  time.


## 1.1

- Make QR codes less dense so they are easier to scan.


## 1.0

Initial release.
- Split secrets into data files or QR code outputs.
- Recover them from data file or QR code inputs.
