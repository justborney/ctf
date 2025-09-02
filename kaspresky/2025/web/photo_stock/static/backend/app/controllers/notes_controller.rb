class NotesController < ApplicationController
  before_action :set_note, only: [:show, :update, :destroy]

  def index
    render json: Note.includes(:user).order(created_at: :desc).map { |note| render_note(note) }
  end

  def show
    return render_forbidden unless @note.user_id == current_user.id
    render json: render_note(@note)
  end

  def create
    @note = current_user.notes.build(note_params)
    
    if @note.save
      @note.save_image_to_file
      render json: render_note(@note), status: :created
    else
      render json: @note.errors, status: :unprocessable_entity
    end
  end

  def update
    return render_forbidden unless @note.user_id == current_user.id
    
    if @note.update(note_params)
      @note.save_image_to_file
      render json: render_note(@note)
    else
      render json: @note.errors, status: :unprocessable_entity
    end
  end

  def destroy
    return render_forbidden unless @note.user_id == current_user.id

    if @note.image_path && File.exist?(@note.get_image_path)
      File.delete(@note.get_image_path)
    end

    @note.destroy!
    head :no_content
  end

  def privacy
    privacy = params[:privacy]
    return render_bad_request("Privacy must be 'private' or 'public'") unless %w[private public].include?(privacy)

    if params[:_json].is_a?(Array)
      params[:_json].each do |note_id| 
        return render_forbidden unless Note.find_by(id: note_id).user_id == current_user.id
        Note.where(id: note_id).update(privacy: privacy)
      end
    else
      return render_forbidden unless Note.find_by(id: params[:id]).user_id == current_user.id
    end

    if params[:id]
      Note.find_by(id: params[:id]).update(privacy: privacy)
    end

    render_success
  end


  def image
    note = Note.find(params[:id])
    return render_not_found unless note

    return render_not_found unless note.image_path.present?

    image_path = note.get_image_path
    return render_not_found unless image_path && File.exist?(image_path)

    if note.can_user_see_image?(current_user)
      send_file image_path, type: 'image/jpeg', disposition: 'inline'
    else
      blurred_image_path = ImageService.create_blurred_image(image_path)
      send_file blurred_image_path, type: 'image/jpeg', disposition: 'inline'
    end
  rescue ActiveRecord::RecordNotFound
    render_not_found
  end

  private

  def set_note
    @note = Note.find(params[:id])
  rescue ActiveRecord::RecordNotFound
    render json: { error: "Note not found" }, status: :not_found
  end

  def note_params
    params.require(:note).permit(:title, :privacy, :image_data)
  end

  def render_note(note)
    result = {
      id: note.id,
      title: note.title,
      image_url: "/notes/#{note.id}/image",
      privacy: note.privacy,
      owner: note.user.username,
      created_at: note.created_at,
      updated_at: note.updated_at,
      is_owner: current_user && note.user_id == current_user.id
    }
    result
  end

  def render_forbidden
    render status: :forbidden
  end

  def render_success
    render status: :ok
  end

  def render_not_found
    render status: :not_found
  end

  def render_bad_request(message)
    render status: :bad_request
  end
end
