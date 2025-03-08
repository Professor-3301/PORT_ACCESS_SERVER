from django.shortcuts import render
from django.http import HttpResponse

def home(request):
    return render(request, "home.html")

def about(request):
    return render(request, "about.html")

def features(request):
    return render(request, "features.html")

def downloads(request):
    return render(request, "downloads.html")

def contact(request):
    return render(request, "contact.html")
