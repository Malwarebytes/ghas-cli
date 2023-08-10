This PR creates the Security scanning (CodeQL) configuration files for your repository languages.

We also just opened an informative issue in this repository to give you the context and assistance you need. In most cases you will be able to merge this PR as is and start benefiting from security scanning right away, as a check in each PR, and in the [Security tab](https://github.com/{organization}/{repository}/security/code-scanning) of this repository. 

However, we encourage you to review the configuration files and ask questions in the Teams `Corp DevOps / Github Community` channel. if you have any questions.

Please note: For this pull request to pass and be mergeable, you will need to update the languages array in the codeql yml file with the languages that your repository is using (eg. python, csharp, ruby, go, etc). Not all languages are supported, so only merge this change if at least one language in the repo is in this [Supported Languages](https://codeql.github.com/docs/codeql-overview/supported-languages-and-frameworks/) list. GitHub is continually adding languages to the support list, so if a language is not supported now it very well may be soon. If your repository does not contain code in one of these supported languages, please do not merge this pull request until there is support. If you merge it without adding a supported language, the pull request checks will fail and you will be unable to merge the pull request.

We are here to help! :thumbsup:

Regards,

Github Admins
