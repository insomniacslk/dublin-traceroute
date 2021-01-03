#!/bin/bash
set -exu

echo "${DOCKER_PASSWORD}" | docker login -u "${DOCKER_USERNAME}" --password-stdin
docker push "${TRAVIS_REPO_SLUG}"
if [ "${TRAVIS_BRANCH}" != "master" ]; then
  docker tag "${TRAVIS_REPO_SLUG}" "${TRAVIS_REPO_SLUG}:${TRAVIS_BRANCH}"
  docker push "${TRAVIS_REPO_SLUG}:${TRAVIS_BRANCH}"
fi
