<?php

namespace App\Http\Controllers;

use App\Models\Task;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Auth;

class TaskController extends Controller {
    /**
     * Display a listing of the resource.
     */
    public function index() {
        return Auth::user()->tasks;
    }

    /**
     * Store a newly created resource in storage.
     */
    public function store(Request $request) {
        $validated = $request->validate([
            'content' => 'required|string|max:250'
        ]);

        $task = Auth::user()->tasks()->create($validated);

        if ($task) {
            return response()->json([
                'message' => 'Task created successfully.',
                'task' => $task,
            ], Response::HTTP_CREATED);
        } else {
            return response()->json([
                'error' => 'Provide proper details'
            ], Response::HTTP_BAD_REQUEST);
        }
    }

    /**
     * Display the specified resource.
     */
    public function show(Task $task) {
        if ($task->user_id !== auth()->id()) {
            return response()->json([
                'error' => 'Unauthorized'
            ], Response::HTTP_UNAUTHORIZED);
        }
        return response()->json([
            'task' => $task
        ]);
    }

    /**
     * Update the specified resource in storage.
     */
    public function update(Request $request, Task $task) {
        if ($task->user_id !== auth()->id()) {
            return response()->json([
                'error' => 'Unauthorized'
            ], Response::HTTP_UNAUTHORIZED);
        }

        $request->validate([
            'content' => 'required|string|max:250'
        ]);

        $task->update($request->only('content'));

        return response()->json([
            'message' => 'Task updated successfully',
            'task' => $task,
        ]);
    }

    /**
     * Remove the specified resource from storage.
     */
    public function destroy(Task $task) {
        if ($task->user_id !== auth()->id()) {
            return response()->json([
                'error' => 'Unauthorized'
            ], Response::HTTP_UNAUTHORIZED);
        }
        $task->delete();
        return response()->json([
            'message' => 'Task deleted successfully'
        ], Response::HTTP_OK);
    }
}
