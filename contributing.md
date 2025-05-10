# Contributing

_This guide is based on the [Bisq contributing guide](https://github.com/bisq-network/bisq/blob/master/CONTRIBUTING.md)._

Anyone is welcome to contribute to Mostro. If you're looking for somewhere to start contributing, check out the [good first issue](https://github.com/MostroP2P/mostro/labels/good%20first%20issue) list.

## Communication Channels

Most communication about technical issues on Mostro happens on the development [Telegram group](https://t.me/mostro_dev), non-technical discussions happen on [Mostro general discussion Telegram group](https://t.me/MostroP2P). Discussion about code changes happens in GitHub issues and pull requests.

## Contributor Workflow

All Mostro contributors submit changes via pull requests. The workflow is as follows:

- Fork the repository
- Create a topic branch from the `main` branch
- Commit patches
- Squash redundant or unnecessary commits
- Submit a pull request from your topic branch back to the `main` branch of the main repository
- Address reviewer feedback and request a re-review

Pull requests should be focused on a single change. Do not mix, for example, refactorings with a bug fix or implementation of a new feature. This practice makes it easier for fellow contributors to review each pull request.

## Reviewing Pull Requests

Mostro follows the review workflow established by the Bitcoin Core project. The following is adapted from the [Bitcoin Core contributor documentation](https://github.com/bitcoin/bitcoin/blob/master/CONTRIBUTING.md#peer-review):

Anyone may participate in peer review, which is expressed by comments in the pull request. Typically, reviewers will review the code for obvious errors, test the patch set, and opine on its technical merits. Project maintainers consider peer review when determining whether there is consensus to merge a pull request (discussions may be spread across GitHub and Telegram).

- `ACK` means "I have tested the code and I agree it should be merged";
- `utACK` means "I have not tested the code, but I have reviewed. It looks OK, and I agree it can be merged";
- `Concept ACK` means "I agree with the general principle of this pull request";
- `NACK` means "I disagree this should be merged", and must be accompanied by sound technical justification. NACKs without accompanying reasoning may be disregarded;
- `Nit` refers to trivial, often non-blocking issues.

Please note that Pull Requests marked `NACK` and/or GitHub's `Change requested` are closed after 30 days if not addressed.

## Code formatting

Run `cargo fmt` and `cargo clippy` before committing to ensure that code is consistently formatted.

### Configure Git username and email metadata

See <https://help.github.com/articles/setting-your-username-in-git/> for instructions.

### Write well-formed commit messages

From <https://chris.beams.io/posts/git-commit/#seven-rules>:

1. Separate subject from body with a blank line
2. Limit the subject line to 50 characters
3. Capitalize the subject line
4. Do not end the subject line with a period
5. Use the imperative mood in the subject line
6. Wrap the body at 72 characters
7. Use the body to explain what and why vs. how

### Sign your commits with GPG

See <https://github.com/blog/2144-gpg-signature-verification> for background and
<https://help.github.com/articles/signing-commits-with-gpg/> for instructions.

### Keep the git history clean

It's important to keep the git history clear, light, and easily browsable. This means contributors must make sure their pull requests include only meaningful commits (if they are redundant or were added after a review, they should be removed) and _no merge commits_.
