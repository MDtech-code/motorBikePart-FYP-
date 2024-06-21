from django.urls import path
from . import views
urlpatterns = [
    path('',views.ProductViews.as_view(),name='products'),
    path('product_detail/<str:pk>/',views.ProductDetailViews.as_view(),name='product_detail'),
    path('cart/', views.CartDetailView.as_view(), name='cart-detail'),
    path('add-to-cart/', views.AddToCartView.as_view(), name='add-to-cart'),
    path('cart-item-update/<int:pk>/', views.UpdateCartItemView.as_view(), name='update-cart-item'),
    path('cart-item-delete/<int:pk>/', views.RemoveFromCartView.as_view(), name='remove-from-cart-item'),
]
