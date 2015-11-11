#
# Example R code to install packages
# See http://cran.r-project.org/doc/manuals/R-admin.html#Installing-packages for details
#

###########################################################
# Update this line with the R packages to install:

my_packages = c("nlme", "devtools", "dplyr", "tidyr", "reshape2")
git_packages = c("jayjacobs/verisr", "Rdatatable/data.table")

###########################################################

install_if_missing = function(p) {
  if (p %in% rownames(installed.packages()) == FALSE) {
    install.packages(p, dependencies = TRUE)
  }
  else {
    cat(paste("Skipping already installed normal package:", p, "\n"))
  }
}
install_if_missing_github = function(p) {
  if (p %in% rownames(installed.packages()) == FALSE) {
    devtools::install_github(p, dependencies = TRUE)
  }
  else {
    cat(paste("Skipping already installed github package:", p, "\n"))
  }
}
invisible(sapply(my_packages, install_if_missing))
invisible(sapply(git_packages, install_if_missing_github))
