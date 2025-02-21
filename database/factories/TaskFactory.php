<?php

namespace Database\Factories;

use App\Models\User;
use Illuminate\Database\Eloquent\Factories\Factory;

/**
 * @extends \Illuminate\Database\Eloquent\Factories\Factory<\App\Models\Task>
 */
class TaskFactory extends Factory {
    /**
     * Define the model's default state.
     *
     * @return array<string, mixed>
     */
    public function definition(): array {
        return [
            'user_id' => User::inRandomOrder()->first()->id,
            'content' => fake()->realText(100),
            'is_finished' => fake()->boolean(),
            'finished_at' => fake()->randomElement([null, now()]),
        ];
    }
}
