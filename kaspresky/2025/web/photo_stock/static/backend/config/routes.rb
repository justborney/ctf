Rails.application.routes.draw do
  post 'auth/register', to: 'auth#register'
  post 'auth/login', to: 'auth#login'
  get 'auth/me', to: 'auth#me'

  get 'notes', to: 'notes#index'
  post 'notes', to: 'notes#create'
  get 'notes/:id', to: 'notes#show'
  get 'notes/:id/image', to: 'notes#image'
  patch 'notes/:privacy', to: 'notes#privacy'
  put 'notes/:id', to: 'notes#update'
  delete 'notes/:id', to: 'notes#destroy'
end
