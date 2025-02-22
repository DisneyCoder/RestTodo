<?php

namespace App\Models;

use App\Models\User;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Factories\HasFactory;

class Task extends Model {
    /** @use HasFactory<\Database\Factories\TaskFactory> */
    use HasFactory;

    protected $guarded = [];

    protected function casts() {
        return [
            'is_finished' => 'boolean',
            'finished_at' => 'datetime',
        ];
    }
    public function user() {
        return $this->belongsTo(User::class);
    }
}
