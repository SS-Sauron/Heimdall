# Contributing to Heimdall

First off, thank you for considering contributing to Heimdall! It's people like you that make Heimdall such a great tool.

## Setting up your environment

1. **Install ESP-IDF v6**: Heimdall requires ESP-IDF version 6.0.1 or newer. Please follow the official [Espressif setup guide](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/get-started/).
2. **Clone the repository**: `git clone https://github.com/SS-Sauron/Heimdall.git`
3. **Build the project**: Run `idf.py build` to ensure your environment is set up correctly.

## Coding Standards

* **Language**: C99.
* **Style**: We generally follow the ESP-IDF coding style. Please ensure your code is readable, modular, and well-commented.
* **Architecture**: Keep features within their respective components in the `components/` directory. Do not introduce global state.

## Pull Request Process

1. Fork the repo and create your branch from `main`.
2. If you've added code that should be tested, add tests.
3. Ensure the test suite passes.
4. Update the `README.md` or `docs/README.md` with details of changes to the interface or architecture.
5. Issue that pull request!

## Reporting Bugs

Please use the provided Issue Templates to report bugs, ensuring you include your hardware details, ESP-IDF version, and relevant logs.
