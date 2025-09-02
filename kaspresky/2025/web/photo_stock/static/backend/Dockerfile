FROM ruby:3.4.5

WORKDIR /app

COPY Gemfile ./

RUN bundle update
RUN bundle install

COPY . .

RUN chmod +x entrypoint.sh

EXPOSE 3000

CMD ["sh", "entrypoint.sh"]
