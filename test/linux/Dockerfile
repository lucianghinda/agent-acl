FROM ruby:3.2

RUN apt-get update
RUN apt-get install --yes e2fsprogs
RUN gem install zeitwerk --version "~> 2.8" --no-document

WORKDIR /app

CMD ["ruby", "-Ilib", "test/linux/run.rb"]
