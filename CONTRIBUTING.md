# Contributing to Lotus
===========================

The Lotus project welcomes contributors!

This guide is intended to help developers contribute effectively to Lotus.

## Communicating with Developers

To get in contact with Lotus developers, we monitor a Telegram channel. The intent of this channel is specifically to facilitate development of Lotus, and to welcome people who wish to participate.

[Join the Lotus Telegram Channel](https://t.me/givelotus)

You can also directly contact the maintainers:
- Alex: [@Alex3676](https://t.me/Alex3676)
- Matthew: [@maff1989](https://t.me/maff1989)

Acceptable use of this channel includes the following:
* Introducing yourself to other Lotus developers.
* Getting help with your development environment.
* Discussing how to complete a patch.

It is not for:
* Market discussion
* Non-constructive criticism

## Lotus Development Philosophy

Lotus aims for fast iteration and continuous integration.

This means that there should be quick turnaround for patches to be proposed, reviewed, and committed. Changes should not sit in a queue for long.

Here are some tips to help keep the development working as intended:

- Keep each change small and self-contained.
- Reach out for a 1-on-1 review so things move quickly.
- Land the Diff quickly after it is accepted.
- Don't amend changes after the Diff accepted, new Diff for another fix.
- Review Diffs from other developers as quickly as possible.
- Large changes should be broken into logical chunks that are easy to review, and keep the code in a functional state.
- Do not mix moving stuff around with changing stuff. Do changes with renames on their own.
- As soon as you see a bug, you fix it. Do not continue on. Fixing the bug becomes the top priority, more important than completing other tasks.
- Automate as much as possible, and spend time on things only humans can do.

## Getting set up with the Lotus Repository

1. Clone the repository:
```
git clone https://github.com/givelotus/lotus.git
cd lotus
```

2. Set up your development environment following the build instructions in [INSTALL.md](INSTALL.md)

## Development Workflow

A typical workflow would be:

- Create a topic branch in Git for your changes
  ```
  git checkout -b 'my-topic-branch'
  ```

- Make your changes, and commit them
  ```
  git commit -a -m 'my-commit'
  ```

- Create a pull request through GitHub

- Once your PR is approved and merged, you have successfully contributed to Lotus!

## What to work on

If you are looking for a useful task to contribute to the project, check the GitHub issues list or ask in the Telegram channel for current priorities.

## Copyright

By contributing to this repository, you agree to license your work under the MIT license unless specified otherwise in `contrib/debian/copyright` or at the top of the file itself. Any work contributed where you are not the original author must contain its license header with the original author(s) and source.

## Disclosure Policy

See [DISCLOSURE_POLICY](DISCLOSURE_POLICY.md).
