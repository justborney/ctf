class CreateNotes < ActiveRecord::Migration[8.0]
  def change
    create_table :notes, id: :uuid do |t|
      t.string :title, null: false
      t.text :image_data
      t.string :image_path
      t.string :user_id, null: false
      t.string :privacy, default: 'private', null: false

      t.timestamps
    end
    add_index :notes, :user_id
    add_index :notes, :image_path
    add_index :notes, :privacy
  end
end
