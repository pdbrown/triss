## 2.0a1

- **Breaking change**: Bump MacHeader version from 1 to 2.
  - Add `payload_size`, 4 byte int field.
  - Shrink `algroithm` field from 24 -> 20 bytes.
- Add webcam QR code scanner powered by `zbarcam`.

## 1.1

- Make QR codes less dense so they are easier to scan.

## 1.0

The initial release.
- Split secrets into data files or QR code outputs.
- Recover them from data file or QR code inputs.
