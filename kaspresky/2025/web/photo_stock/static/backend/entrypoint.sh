rails db:drop
rm db/schema.rb &>/dev/null
rm tmp/pids/server.pid &>/dev/null
rm storage/images/* &>/dev/null
rails db:create
rails db:migrate
rails db:seed
rails server -b 0.0.0.0