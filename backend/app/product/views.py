from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.pagination import PageNumberPagination
from .models import Product,Cart,CartItem
from .serializers import ProductSerializer,ProductDetailSerializer,CartSerializer,CartItemSerializer
from django.shortcuts import get_object_or_404
from django.contrib.auth.decorators import login_required
from django.utils.decorators import method_decorator

# Create your views here.
class ProductViews(APIView):
    def get(self,request):
        product=Product.objects.all()
        paginator=PageNumberPagination()
        paginator.page_size=3
        paginated_products=paginator.paginate_queryset(product,request)
        serializer=ProductSerializer(paginated_products, many=True)
        return Response(serializer.data,status=status.HTTP_200_OK)
    
class ProductDetailViews(APIView):
    def get(self,request,pk):
        product_detail=get_object_or_404(Product,pk)
        serializer=ProductDetailSerializer(product_detail)
        return Response(serializer.data,status=status.HTTP_200_OK)


class CartDetailView(APIView):
    @method_decorator(login_required)
    def get(self, request):
        try:
            cart = Cart.objects.get(user=request.user)
            serializer = CartSerializer(cart)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Cart.DoesNotExist:
            return Response({'message': 'Cart does not exist'}, status=status.HTTP_404_NOT_FOUND)

class AddToCartView(APIView):
    def post(self, request):
        # Deserialize request data to create a new CartItem
        serializer = CartItemSerializer(data=request.data)
        if serializer.is_valid():
            product_id = serializer.validated_data['product'].id
            quantity = serializer.validated_data['quantity']

            # Get or create cart for the current user
            cart, created = Cart.objects.get_or_create(user=request.user)

            # Add or update the quantity of the product in the cart
            cart_item, created = CartItem.objects.update_or_create(
                cart=cart,
                product_id=product_id,
                defaults={'quantity': quantity}
            )

            return Response({'message': 'Item added to cart successfully'}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class UpdateCartItemView(APIView):
    @method_decorator(login_required)
    def put(self, request, pk):
        cart_item = get_object_or_404(CartItem, pk=pk)
        

        # Deserialize request data to update the CartItem
        serializer = CartItemSerializer(cart_item, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class RemoveFromCartView(APIView):
    @method_decorator(login_required)
    def delete(self, request, pk):
        cart_item = get_object_or_404(CartItem, pk=pk)
        cart_item.delete()
        return Response({'message': 'Item removed from cart successfully'}, status=status.HTTP_204_NO_CONTENT)