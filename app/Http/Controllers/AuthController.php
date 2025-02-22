<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;

class AuthController extends Controller {


    public function register(Request $request) {
        $validated = $request->validate([
            'name' => 'required|string|max:100',
            'email' => 'required|email|unique:users',
            'password' => 'required|string|min:6|confirmed',
        ]);

        // Hash the password before saving
        $validated['password'] = Hash::make($validated['password']);

        $user = User::create($validated);
        if (!$user) {
            return response()->json([
                'message' => 'Failed to register the user',
                'error' => 'User creation failed',
            ], Response::HTTP_BAD_REQUEST);
        }

        return response()->json([
            'message' => 'User created successfully!',
            'token' => $user->createToken("TaskTokenKey")->plainTextToken
        ], Response::HTTP_CREATED);
    }

    public function login(Request $request) {
        $credential = $request->validate([
            'email' => 'required|email',
            'password' => 'required|string|min:6',
        ]);

        if (!Auth::attempt($credential)) {
            return response()->json([
                'message' => 'Credentials do not match.',
            ], Response::HTTP_UNAUTHORIZED);
        }

        $user = $request->user();
        return response()->json([
            'message' => 'Login Successful',
            'token' => $user->createToken('userTokenKey')->plainTextToken
        ], Response::HTTP_OK);
    }

    public function logout(Request $request) {
        // Logout the user and revoke all tokens
        $request->user()->tokens()->delete();

        return response()->json([
            'message' => 'Logged out successfully',
        ], Response::HTTP_OK);
    }
}
