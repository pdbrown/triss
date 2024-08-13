## 2.0a1

### BREAKING Changes
- Bump MacHeader version from 1 to 2 and drop support for version 1.
  - Add `payload_size`, 4 byte int field.
  - Shrink `algroithm` field from 24 -> 20 bytes.

### Changes
- Add webcam QR code scanner powered by `zbarcam`.
- Support multiple QR codes per input image.

## 1.1

- Make QR codes less dense so they are easier to scan.

## 1.0

The initial release.
- Split secrets into data files or QR code outputs.
- Recover them from data file or QR code inputs.
